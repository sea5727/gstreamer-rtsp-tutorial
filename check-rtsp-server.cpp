
#include <gst/check/gstcheck.h>
#include <gst/rtsp/gstrtspmessage.h>
#include <gst/sdp/gstsdpmessage.h>
#include <gst/rtp/gstrtcpbuffer.h>
#include <gst/rtp/gstrtpbuffer.h>


#include <stdio.h>
#include <netinet/in.h>

#include <gst/rtsp-server/rtsp-server.h>

#define VIDEO_PIPELINE "videotestsrc ! " \
  "video/x-raw,width=352,height=288 ! " \
  "rtpgstpay name=pay0 pt=96"
#define AUDIO_PIPELINE "audiotestsrc ! " \
  "audio/x-raw,rate=8000 ! " \
  "rtpgstpay name=pay1 pt=97"

#define TEST_MOUNT_POINT  "/test"
#define TEST_PROTO        "RTP/AVP"
#define TEST_ENCODING     "X-GST"
#define TEST_CLOCK_RATE   "90000"

/* tested rtsp server */
static GstRTSPServer *server = NULL;

/* tcp port that the test server listens for rtsp requests on */
static gint test_port = 0;

/* id of the server's source within the GMainContext */
static guint source_id;

/* iterate the default main loop until there are no events to dispatch */
static void
iterate (void)
{
  while (g_main_context_iteration (NULL, FALSE)) {
    GST_DEBUG ("iteration");
  }
}


/* stop the tested rtsp server */
static void
stop_server (void)
{
  g_source_remove (source_id);
  source_id = 0;

  GST_DEBUG ("rtsp server stopped");
}

static void
get_client_ports_full (GstRTSPRange * range, GSocket ** rtp_socket,
    GSocket ** rtcp_socket)
{
  GSocket *rtp = NULL;
  GSocket *rtcp = NULL;
  gint rtp_port = 0;
  gint rtcp_port;
  GInetAddress *anyaddr = g_inet_address_new_any (G_SOCKET_FAMILY_IPV4);
  GSocketAddress *sockaddr;
  gboolean bound;

  for (;;) {
    if (rtp_port != 0)
      rtp_port += 2;

    rtp = g_socket_new (G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM,
        G_SOCKET_PROTOCOL_UDP, NULL);
    fail_unless (rtp != NULL);

    sockaddr = g_inet_socket_address_new (anyaddr, rtp_port);
    fail_unless (sockaddr != NULL);
    bound = g_socket_bind (rtp, sockaddr, FALSE, NULL);
    g_object_unref (sockaddr);
    if (!bound) {
      g_object_unref (rtp);
      continue;
    }

    sockaddr = g_socket_get_local_address (rtp, NULL);
    fail_unless (sockaddr != NULL && G_IS_INET_SOCKET_ADDRESS (sockaddr));
    rtp_port =
        g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (sockaddr));
    g_object_unref (sockaddr);

    if (rtp_port % 2 != 0) {
      rtp_port += 1;
      g_object_unref (rtp);
      continue;
    }

    rtcp_port = rtp_port + 1;

    rtcp = g_socket_new (G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM,
        G_SOCKET_PROTOCOL_UDP, NULL);
    fail_unless (rtcp != NULL);

    sockaddr = g_inet_socket_address_new (anyaddr, rtcp_port);
    fail_unless (sockaddr != NULL);
    bound = g_socket_bind (rtcp, sockaddr, FALSE, NULL);
    g_object_unref (sockaddr);
    if (!bound) {
      g_object_unref (rtp);
      g_object_unref (rtcp);
      continue;
    }

    sockaddr = g_socket_get_local_address (rtcp, NULL);
    fail_unless (sockaddr != NULL && G_IS_INET_SOCKET_ADDRESS (sockaddr));
    fail_unless (rtcp_port ==
        g_inet_socket_address_get_port (G_INET_SOCKET_ADDRESS (sockaddr)));
    g_object_unref (sockaddr);

    break;
  }

  range->min = rtp_port;
  range->max = rtcp_port;
  if (rtp_socket)
    *rtp_socket = rtp;
  else
    g_object_unref (rtp);
  if (rtcp_socket)
    *rtcp_socket = rtcp;
  else
    g_object_unref (rtcp);
  GST_DEBUG ("client_port=%d-%d", range->min, range->max);
  g_object_unref (anyaddr);
}

/* get a free rtp/rtcp client port pair */
static void
get_client_ports (GstRTSPRange * range)
{
  get_client_ports_full (range, NULL, NULL);
}

/* start the tested rtsp server */
static void
start_server (gboolean set_shared_factory)
{
  GstRTSPMountPoints *mounts;
  gchar *service;
  GstRTSPMediaFactory *factory;
  GstRTSPAddressPool *pool;

  mounts = gst_rtsp_server_get_mount_points (server);

  factory = gst_rtsp_media_factory_new ();

  gst_rtsp_media_factory_set_launch (factory,
      "( " VIDEO_PIPELINE "  " AUDIO_PIPELINE " )");
  gst_rtsp_mount_points_add_factory (mounts, TEST_MOUNT_POINT, factory);
  g_object_unref (mounts);

  /* use an address pool for multicast */
  pool = gst_rtsp_address_pool_new ();
  gst_rtsp_address_pool_add_range (pool,
      "224.3.0.0", "224.3.0.10", 5500, 5510, 16);
  gst_rtsp_address_pool_add_range (pool, GST_RTSP_ADDRESS_POOL_ANY_IPV4,
      GST_RTSP_ADDRESS_POOL_ANY_IPV4, 6000, 6010, 0);
  gst_rtsp_media_factory_set_address_pool (factory, pool);
  gst_rtsp_media_factory_set_shared (factory, set_shared_factory);
  gst_object_unref (pool);

  /* set port to any */
  gst_rtsp_server_set_service (server, "0");

  /* attach to default main context */
  source_id = gst_rtsp_server_attach (server, NULL);
  fail_if (source_id == 0);

  /* get port */
  service = gst_rtsp_server_get_service (server);
  test_port = atoi (service);
  fail_unless (test_port != 0);
  g_free (service);

  GST_DEBUG ("rtsp server listening on port %d", test_port);
}

/* create an rtsp connection to the server on test_port */
static GstRTSPConnection *
connect_to_server (gint port, const gchar * mount_point)
{
  GstRTSPConnection *conn = NULL;
  gchar *address;
  gchar *uri_string;
  GstRTSPUrl *url = NULL;

  address = gst_rtsp_server_get_address (server);
  uri_string = g_strdup_printf ("rtsp://%s:%d%s", address, port, mount_point);
  g_free (address);
  fail_unless (gst_rtsp_url_parse (uri_string, &url) == GST_RTSP_OK);
  g_free (uri_string);

  fail_unless (gst_rtsp_connection_create (url, &conn) == GST_RTSP_OK);
  gst_rtsp_url_free (url);

  fail_unless (gst_rtsp_connection_connect (conn, NULL) == GST_RTSP_OK);

  return conn;
}


/* create an rtsp request */
static GstRTSPMessage *
create_request (GstRTSPConnection * conn, GstRTSPMethod method,
    const gchar * control)
{
  GstRTSPMessage *request = NULL;
  gchar *base_uri;
  gchar *full_uri;

  base_uri = gst_rtsp_url_get_request_uri (gst_rtsp_connection_get_url (conn));
  full_uri = g_strdup_printf ("%s/%s", base_uri, control ? control : "");
  g_free (base_uri);
  if (gst_rtsp_message_new_request (&request, method, full_uri) != GST_RTSP_OK) {
    GST_DEBUG ("failed to create request object");
    g_free (full_uri);
    return NULL;
  }
  g_free (full_uri);
  return request;
}

/* send an rtsp request */
static gboolean
send_request (GstRTSPConnection * conn, GstRTSPMessage * request)
{
  if (gst_rtsp_connection_send (conn, request, NULL) != GST_RTSP_OK) {
    GST_DEBUG ("failed to send request");
    return FALSE;
  }
  return TRUE;
}

/* read rtsp response. response must be freed by the caller */
static GstRTSPMessage *
read_response (GstRTSPConnection * conn)
{
  GstRTSPMessage *response = NULL;
  GstRTSPMsgType type;

  if (gst_rtsp_message_new (&response) != GST_RTSP_OK) {
    GST_DEBUG ("failed to create response object");
    return NULL;
  }
  if (gst_rtsp_connection_receive (conn, response, NULL) != GST_RTSP_OK) {
    GST_DEBUG ("failed to read response");
    gst_rtsp_message_free (response);
    return NULL;
  }
  type = gst_rtsp_message_get_type (response);
  fail_unless (type == GST_RTSP_MESSAGE_RESPONSE
      || type == GST_RTSP_MESSAGE_DATA);
  return response;
}


/* send an rtsp request and receive response. gchar** parameters are out
 * parameters that have to be freed by the caller */
static GstRTSPStatusCode
do_request_full (GstRTSPConnection * conn, GstRTSPMethod method,
    const gchar * control, const gchar * session_in, const gchar * transport_in,
    const gchar * range_in, const gchar * require_in,
    gchar ** content_type, gchar ** content_base, gchar ** body,
    gchar ** session_out, gchar ** transport_out, gchar ** range_out,
    gchar ** unsupported_out)
{
  GstRTSPMessage *request;
  GstRTSPMessage *response;
  GstRTSPStatusCode code;
  gchar *value;
  GstRTSPMsgType msg_type;

  /* create request */
  request = create_request (conn, method, control);

  /* add headers */
  if (session_in) {
    gst_rtsp_message_add_header (request, GST_RTSP_HDR_SESSION, session_in);
  }
  if (transport_in) {
    gst_rtsp_message_add_header (request, GST_RTSP_HDR_TRANSPORT, transport_in);
  }
  if (range_in) {
    gst_rtsp_message_add_header (request, GST_RTSP_HDR_RANGE, range_in);
  }
  if (require_in) {
    gst_rtsp_message_add_header (request, GST_RTSP_HDR_REQUIRE, require_in);
  }

 
  /* send request */
  fail_unless (send_request (conn, request));
  gst_rtsp_message_free (request);

  iterate ();

  /* read response */
  response = read_response (conn);
  fail_unless (response != NULL);

  msg_type = gst_rtsp_message_get_type (response);

  if (msg_type == GST_RTSP_MESSAGE_DATA) {
    do {
      gst_rtsp_message_free (response);
      response = read_response (conn);
      msg_type = gst_rtsp_message_get_type (response);
    } while (msg_type == GST_RTSP_MESSAGE_DATA);
  }

  fail_unless (msg_type == GST_RTSP_MESSAGE_RESPONSE);

  /* check status line */
  gst_rtsp_message_parse_response (response, &code, NULL, NULL);
  if (code != GST_RTSP_STS_OK) {
    if (unsupported_out != NULL && code == GST_RTSP_STS_OPTION_NOT_SUPPORTED) {
      gst_rtsp_message_get_header (response, GST_RTSP_HDR_UNSUPPORTED,
          &value, 0);
      *unsupported_out = g_strdup (value);
    }
    gst_rtsp_message_free (response);
    return code;
  }

  /* get information from response */
  if (content_type) {
    gst_rtsp_message_get_header (response, GST_RTSP_HDR_CONTENT_TYPE,
        &value, 0);
    *content_type = g_strdup (value);
  }
  if (content_base) {
    gst_rtsp_message_get_header (response, GST_RTSP_HDR_CONTENT_BASE,
        &value, 0);
    *content_base = g_strdup (value);
  }
  if (body) {
    *body = (gchar *)g_malloc (response->body_size + 1);
    strncpy (*body, (gchar *) response->body, response->body_size);
  }
  if (session_out) {
    gst_rtsp_message_get_header (response, GST_RTSP_HDR_SESSION, &value, 0);

    value = g_strdup (value);

    /* Remove the timeout */
    if (value) {
      char *pos = strchr (value, ';');
      if (pos)
        *pos = 0;
    }
    if (session_in) {
      /* check that we got the same session back */
      fail_unless (!g_strcmp0 (value, session_in));
    }
    *session_out = value;
  }
  if (transport_out) {
    gst_rtsp_message_get_header (response, GST_RTSP_HDR_TRANSPORT, &value, 0);
    *transport_out = g_strdup (value);
  }
  if (range_out) {
    gst_rtsp_message_get_header (response, GST_RTSP_HDR_RANGE, &value, 0);
    *range_out = g_strdup (value);
  }

  gst_rtsp_message_free (response);
  return code;
}

/* send an rtsp request and receive response. gchar** parameters are out
 * parameters that have to be freed by the caller */
static GstRTSPStatusCode
do_request (GstRTSPConnection * conn, GstRTSPMethod method,
    const gchar * control, const gchar * session_in,
    const gchar * transport_in, const gchar * range_in,
    gchar ** content_type, gchar ** content_base, gchar ** body,
    gchar ** session_out, gchar ** transport_out, gchar ** range_out)
{
  return do_request_full (conn, method, control, session_in, transport_in,
      range_in, NULL, content_type, content_base, body, session_out,
      transport_out, range_out, NULL);
}

/* send an rtsp request with a method and a session, and receive response */
static GstRTSPStatusCode
do_simple_request (GstRTSPConnection * conn, GstRTSPMethod method,
    const gchar * session)
{
  return do_request (conn, method, NULL, session, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL);
}


/* send a DESCRIBE request and receive response. returns a received
 * GstSDPMessage that must be freed by the caller */
static GstSDPMessage *
do_describe (GstRTSPConnection * conn, const gchar * mount_point)
{
  GstSDPMessage *sdp_message;
  gchar *content_type = NULL;
  gchar *content_base = NULL;
  gchar *body = NULL;
  gchar *address;
  gchar *expected_content_base;

  /* send DESCRIBE request */
  fail_unless (do_request (conn, GST_RTSP_DESCRIBE, NULL, NULL, NULL, NULL,
          &content_type, &content_base, &body, NULL, NULL, NULL) ==
      GST_RTSP_STS_OK);
//   g_print("strlen(body) : %d\n", strlen (body));
  /* check response values */
  fail_unless (!g_strcmp0 (content_type, "application/sdp"));
  address = gst_rtsp_server_get_address (server);
  expected_content_base =
      g_strdup_printf ("rtsp://%s:%d%s/", address, test_port, mount_point);
  fail_unless (!g_strcmp0 (content_base, expected_content_base));

  /* create sdp message */
  fail_unless (gst_sdp_message_new (&sdp_message) == GST_SDP_OK);
  
  fail_unless (gst_sdp_message_parse_buffer ((guint8 *) body,
          strlen (body), sdp_message) == GST_SDP_OK);

  /* clean up */
  g_free (content_type);
  g_free (content_base);
  g_free (body);
  g_free (address);
  g_free (expected_content_base);

  return sdp_message;
}

/* send a SETUP request and receive response. if *session is not NULL,
 * it is used in the request. otherwise, *session is set to a returned
 * session string that must be freed by the caller. the returned
 * transport must be freed by the caller. */
static GstRTSPStatusCode
do_setup_full (GstRTSPConnection * conn, const gchar * control,
    GstRTSPLowerTrans lower_transport, const GstRTSPRange * client_ports,
    const gchar * require, gchar ** session, GstRTSPTransport ** transport,
    gchar ** unsupported)
{
  GstRTSPStatusCode code;
  gchar *session_in = NULL;
  GString *transport_string_in = NULL;
  gchar **session_out = NULL;
  gchar *transport_string_out = NULL;

  /* prepare and send SETUP request */
  if (session) {
    if (*session) {
      session_in = *session;
    } else {
      session_out = session;
    }
  }

  transport_string_in = g_string_new (TEST_PROTO);
  switch (lower_transport) {
    case GST_RTSP_LOWER_TRANS_UDP:
      transport_string_in =
          g_string_append (transport_string_in, "/UDP;unicast");
      break;
    case GST_RTSP_LOWER_TRANS_UDP_MCAST:
      transport_string_in =
          g_string_append (transport_string_in, "/UDP;multicast");
      break;
    case GST_RTSP_LOWER_TRANS_TCP:
      transport_string_in =
          g_string_append (transport_string_in, "/TCP;unicast");
      break;
    default:
      g_assert_not_reached ();
      break;
  }

  if (client_ports) {
    g_string_append_printf (transport_string_in, ";client_port=%d-%d",
        client_ports->min, client_ports->max);
  }

  code =
      do_request_full (conn, GST_RTSP_SETUP, control, session_in,
      transport_string_in->str, NULL, require, NULL, NULL, NULL, session_out,
      &transport_string_out, NULL, unsupported);
  g_string_free (transport_string_in, TRUE);

  if (transport_string_out) {
    /* create transport */
    fail_unless (gst_rtsp_transport_new (transport) == GST_RTSP_OK);
    fail_unless (gst_rtsp_transport_parse (transport_string_out,
            *transport) == GST_RTSP_OK);
    g_free (transport_string_out);
  }
  GST_INFO ("code=%d", code);
  return code;
}

/* send a SETUP request and receive response. if *session is not NULL,
 * it is used in the request. otherwise, *session is set to a returned
 * session string that must be freed by the caller. the returned
 * transport must be freed by the caller. */
static GstRTSPStatusCode
do_setup (GstRTSPConnection * conn, const gchar * control,
    const GstRTSPRange * client_ports, gchar ** session,
    GstRTSPTransport ** transport)
{
  return do_setup_full (conn, control, GST_RTSP_LOWER_TRANS_UDP, client_ports,
      NULL, session, transport, NULL);
}


/* fixture setup function */
static void
setup (void)
{
  server = gst_rtsp_server_new ();
}
/* fixture clean-up function */
static void
teardown (void)
{
  if (server) {
    g_object_unref (server);
    server = NULL;
  }
  test_port = 0;
}
static void
receive_rtp (GSocket * socket, GSocketAddress ** addr)
{
  GstBuffer *buffer = gst_buffer_new_allocate (NULL, 65536, NULL);

  for (;;) {
    gssize bytes;
    GstMapInfo map = GST_MAP_INFO_INIT;
    GstRTPBuffer rtpbuffer = GST_RTP_BUFFER_INIT;

    gst_buffer_map (buffer, &map, GST_MAP_WRITE);
    bytes = g_socket_receive_from (socket, addr, (gchar *) map.data,
        map.maxsize, NULL, NULL);
    fail_unless (bytes > 0);
    gst_buffer_unmap (buffer, &map);
    gst_buffer_set_size (buffer, bytes);

    if (gst_rtp_buffer_map (buffer, GST_MAP_READ, &rtpbuffer)) {
      gst_rtp_buffer_unmap (&rtpbuffer);
      break;
    }

    if (addr)
      g_clear_object (addr);
  }

  gst_buffer_unref (buffer);
}

static void
receive_rtcp (GSocket * socket, GSocketAddress ** addr, GstRTCPType type)
{
  GstBuffer *buffer = gst_buffer_new_allocate (NULL, 65536, NULL);

  for (;;) {
    gssize bytes;
    GstMapInfo map = GST_MAP_INFO_INIT;

    gst_buffer_map (buffer, &map, GST_MAP_WRITE);
    bytes = g_socket_receive_from (socket, addr, (gchar *) map.data,
        map.maxsize, NULL, NULL);
    fail_unless (bytes > 0);
    gst_buffer_unmap (buffer, &map);
    gst_buffer_set_size (buffer, bytes);

    if (gst_rtcp_buffer_validate (buffer)) {
      GstRTCPBuffer rtcpbuffer = GST_RTCP_BUFFER_INIT;
      GstRTCPPacket packet;

      if (type) {
        fail_unless (gst_rtcp_buffer_map (buffer, GST_MAP_READ, &rtcpbuffer));
        fail_unless (gst_rtcp_buffer_get_first_packet (&rtcpbuffer, &packet));
        do {
          if (gst_rtcp_packet_get_type (&packet) == type) {
            gst_rtcp_buffer_unmap (&rtcpbuffer);
            goto done;
          }
        } while (gst_rtcp_packet_move_to_next (&packet));
        gst_rtcp_buffer_unmap (&rtcpbuffer);
      } else {
        break;
      }
    }

    if (addr)
      g_clear_object (addr);
  }

done:

  gst_buffer_unref (buffer);
}





GST_START_TEST (test_connect)
{
  GstRTSPConnection *conn;

  start_server (FALSE);

  /* connect to server */
  conn = connect_to_server (test_port, TEST_MOUNT_POINT);

  /* clean up */
  gst_rtsp_connection_free (conn);
  stop_server ();

  /* iterate so the clean-up can finish */
  iterate ();
}

GST_END_TEST;

GST_START_TEST (test_describe)
{
  GstRTSPConnection *conn;
  GstSDPMessage *sdp_message = NULL;
  const GstSDPMedia *sdp_media;
  gint32 format;
  gchar *expected_rtpmap;
  const gchar *rtpmap;
  const gchar *control_video;
  const gchar *control_audio;

  start_server (FALSE);

  conn = connect_to_server (test_port, TEST_MOUNT_POINT);

  /* send DESCRIBE request */
  sdp_message = do_describe (conn, TEST_MOUNT_POINT);
  gchar* text = gst_sdp_message_as_text(sdp_message);
  g_print("sdp_message:\n%s\n", text);
  fail_unless (gst_sdp_message_medias_len (sdp_message) == 2);

  /* check video sdp */
  sdp_media = gst_sdp_message_get_media (sdp_message, 0);
  fail_unless (!g_strcmp0 (gst_sdp_media_get_proto (sdp_media), TEST_PROTO));
  fail_unless (gst_sdp_media_formats_len (sdp_media) == 1);
  sscanf (gst_sdp_media_get_format (sdp_media, 0), "%" G_GINT32_FORMAT,
      &format);
  expected_rtpmap =
      g_strdup_printf ("%d " TEST_ENCODING "/" TEST_CLOCK_RATE, format);
  rtpmap = gst_sdp_media_get_attribute_val (sdp_media, "rtpmap");
  fail_unless (!g_strcmp0 (rtpmap, expected_rtpmap));
  g_free (expected_rtpmap);
  control_video = gst_sdp_media_get_attribute_val (sdp_media, "control");
  fail_unless (!g_strcmp0 (control_video, "stream=0"));

  /* check audio sdp */
  sdp_media = gst_sdp_message_get_media (sdp_message, 1);
  fail_unless (!g_strcmp0 (gst_sdp_media_get_proto (sdp_media), TEST_PROTO));
  fail_unless (gst_sdp_media_formats_len (sdp_media) == 1);
  sscanf (gst_sdp_media_get_format (sdp_media, 0), "%" G_GINT32_FORMAT,
      &format);
  expected_rtpmap =
      g_strdup_printf ("%d " TEST_ENCODING "/" TEST_CLOCK_RATE, format);
  rtpmap = gst_sdp_media_get_attribute_val (sdp_media, "rtpmap");
  fail_unless (!g_strcmp0 (rtpmap, expected_rtpmap));
  g_free (expected_rtpmap);
  control_audio = gst_sdp_media_get_attribute_val (sdp_media, "control");
  fail_unless (!g_strcmp0 (control_audio, "stream=1"));

  /* clean up and iterate so the clean-up can finish */
  gst_sdp_message_free (sdp_message);
  gst_rtsp_connection_free (conn);
  stop_server ();
  iterate ();
}

GST_END_TEST;

static void
do_test_multiple_transports (GstRTSPLowerTrans trans1, GstRTSPLowerTrans trans2)
{
  GstRTSPConnection *conn1;
  GstRTSPConnection *conn2;
  GstSDPMessage *sdp_message1 = NULL;
  GstSDPMessage *sdp_message2 = NULL;
  const GstSDPMedia *sdp_media;
  const gchar *video_control;
  const gchar *audio_control;
  GstRTSPRange client_port1, client_port2;
  gchar *session1 = NULL;
  gchar *session2 = NULL;
  GstRTSPTransport *video_transport = NULL;
  GstRTSPTransport *audio_transport = NULL;
  GSocket *rtp_socket, *rtcp_socket;

  conn1 = connect_to_server (test_port, TEST_MOUNT_POINT);
  conn2 = connect_to_server (test_port, TEST_MOUNT_POINT);

  sdp_message1 = do_describe (conn1, TEST_MOUNT_POINT);

  get_client_ports_full (&client_port1, &rtp_socket, &rtcp_socket);
  /* get control strings from DESCRIBE response */
  sdp_media = gst_sdp_message_get_media (sdp_message1, (GstRTCPType)0);
  video_control = gst_sdp_media_get_attribute_val (sdp_media, "control");
  sdp_media = gst_sdp_message_get_media (sdp_message1, (GstRTCPType)1);
  audio_control = gst_sdp_media_get_attribute_val (sdp_media, "control");

  /* do SETUP for video and audio */
  fail_unless (do_setup_full (conn1, video_control, trans1,
          &client_port1, NULL, &session1, &video_transport,
          NULL) == GST_RTSP_STS_OK);
  fail_unless (do_setup_full (conn1, audio_control, trans1,
          &client_port1, NULL, &session1, &audio_transport,
          NULL) == GST_RTSP_STS_OK);

  gst_rtsp_transport_free (video_transport);
  gst_rtsp_transport_free (audio_transport);

  sdp_message2 = do_describe (conn2, TEST_MOUNT_POINT);

  /* get control strings from DESCRIBE response */
  sdp_media = gst_sdp_message_get_media (sdp_message2, 0);
  video_control = gst_sdp_media_get_attribute_val (sdp_media, "control");
  sdp_media = gst_sdp_message_get_media (sdp_message2, 1);
  audio_control = gst_sdp_media_get_attribute_val (sdp_media, "control");

  get_client_ports_full (&client_port2, NULL, NULL);
  /* do SETUP for video and audio */
  fail_unless (do_setup_full (conn2, video_control, trans2,
          &client_port2, NULL, &session2, &video_transport,
          NULL) == GST_RTSP_STS_OK);
  fail_unless (do_setup_full (conn2, audio_control, trans2,
          &client_port2, NULL, &session2, &audio_transport,
          NULL) == GST_RTSP_STS_OK);

  /* send PLAY request and check that we get 200 OK */
  fail_unless (do_request (conn1, GST_RTSP_PLAY, NULL, session1, NULL, NULL,
          NULL, NULL, NULL, NULL, NULL, NULL) == GST_RTSP_STS_OK);
  /* send PLAY request and check that we get 200 OK */
  fail_unless (do_request (conn2, GST_RTSP_PLAY, NULL, session2, NULL, NULL,
          NULL, NULL, NULL, NULL, NULL, NULL) == GST_RTSP_STS_OK);


  /* receive UDP data */
  receive_rtp (rtp_socket, NULL);
  receive_rtcp (rtcp_socket, NULL, (GstRTCPType)0);

  /* receive TCP data */
  {
    GstRTSPMessage *message;
    fail_unless (gst_rtsp_message_new (&message) == GST_RTSP_OK);
    fail_unless (gst_rtsp_connection_receive (conn2, message,
            NULL) == GST_RTSP_OK);
    fail_unless (gst_rtsp_message_get_type (message) == GST_RTSP_MESSAGE_DATA);
    gst_rtsp_message_free (message);
  }

  /* send TEARDOWN request and check that we get 200 OK */
  fail_unless (do_simple_request (conn1, GST_RTSP_TEARDOWN,
          session1) == GST_RTSP_STS_OK);
  /* send TEARDOWN request and check that we get 200 OK */
  fail_unless (do_simple_request (conn2, GST_RTSP_TEARDOWN,
          session2) == GST_RTSP_STS_OK);

  /* clean up and iterate so the clean-up can finish */
  g_object_unref (rtp_socket);
  g_object_unref (rtcp_socket);
  g_free (session1);
  g_free (session2);
  gst_rtsp_transport_free (video_transport);
  gst_rtsp_transport_free (audio_transport);
  gst_sdp_message_free (sdp_message1);
  gst_sdp_message_free (sdp_message2);
  gst_rtsp_connection_free (conn1);
  gst_rtsp_connection_free (conn2);
}

GST_START_TEST (test_multiple_transports)
{
  start_server (TRUE);
  do_test_multiple_transports (GST_RTSP_LOWER_TRANS_UDP,
      GST_RTSP_LOWER_TRANS_TCP);
  stop_server ();
}

GST_END_TEST;



static Suite *
rtspserver_suite (void)
{
  Suite *s = suite_create ("rtspserver");
  TCase *tc = tcase_create ("general");

  suite_add_tcase (s, tc);
  tcase_add_checked_fixture (tc, setup, teardown);
  tcase_set_timeout (tc, 120);
   tcase_add_test (tc, test_connect);
   tcase_add_test (tc, test_describe);
//   tcase_add_test (tc, test_describe_non_existing_mount_point);
//   tcase_add_test (tc, test_describe_record_media);
//   tcase_add_test (tc, test_setup_udp);
//   tcase_add_test (tc, test_setup_tcp);
//   tcase_add_test (tc, test_setup_udp_mcast);
//   tcase_add_test (tc, test_setup_twice);
//   tcase_add_test (tc, test_setup_with_require_header);
//   tcase_add_test (tc, test_setup_non_existing_stream);
//   tcase_add_test (tc, test_play);
//   tcase_add_test (tc, test_play_tcp);
//   tcase_add_test (tc, test_play_without_session);
//   tcase_add_test (tc, test_bind_already_in_use);
//   tcase_add_test (tc, test_play_multithreaded);
//   tcase_add_test (tc, test_play_multithreaded_block_in_describe);
//   tcase_add_test (tc, test_play_multithreaded_timeout_client);
//   tcase_add_test (tc, test_play_multithreaded_timeout_session);
//   tcase_add_test (tc, test_no_session_timeout);
//   tcase_add_test (tc, test_play_one_active_stream);
//   tcase_add_test (tc, test_play_disconnect);
//   tcase_add_test (tc, test_play_specific_server_port);
//   tcase_add_test (tc, test_play_smpte_range);
//   tcase_add_test (tc, test_play_smpte_range_tcp);
//   tcase_add_test (tc, test_shared);
//   tcase_add_test (tc, test_announce_without_sdp);
//   tcase_add_test (tc, test_record_tcp);
//   tcase_add_test (tc, test_multiple_transports);

  return s;
}
GST_CHECK_MAIN (rtspserver);