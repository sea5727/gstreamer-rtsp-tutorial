cmake_minimum_required(VERSION 3.0.0)
project(test-mp4 VERSION 0.1.0)

include(CTest)
enable_testing()

include(FindPkgConfig)
if(PKG_CONFIG_FOUND)
    message(PKG_CONFIG_FOUND: ${PKG_CONFIG_FOUND} )
    message(PKG_CONFIG_EXECUTABLE: ${PKG_CONFIG_EXECUTABLE} )
    message(PKG_CONFIG_VERSION_STRING: ${PKG_CONFIG_VERSION_STRING} )
    message(PKG_CONFIG: ${PKG_CONFIG} )
    pkg_check_modules(GST gstreamer-1.0)
    pkg_check_modules(GST_SDP gstreamer-sdp-1.0)
    pkg_check_modules(GST_RTSP_SERVER gstreamer-rtsp-server-1.0)
    pkg_check_modules(GST_RTSP gstreamer-rtsp-1.0)
    pkg_check_modules(GST_CHECK gstreamer-check-1.0)
    pkg_check_modules(GST_RTP gstreamer-rtp-1.0)
    
    
    message(GST_INCLUDE_DIRS: ${GST_INCLUDE_DIRS} )
    message(GST_LIBRARY_DIRS: ${GST_LIBRARY_DIRS} )
    message(GST_LIBRARIES: ${GST_LIBRARIES} )
    message(GST_RTSP_SERVER_INCLUDE_DIRS: ${GST_RTSP_SERVER_INCLUDE_DIRS} )
    message(GST_RTSP_SERVER_LIBRARY_DIRS: ${GST_RTSP_SERVER_LIBRARY_DIRS} )
    message(GST_RTSP_SERVER_LIBRARIES: ${GST_RTSP_SERVER_LIBRARIES} )
    message(GST_RTSP_INCLUDE_DIRS: ${GST_RTSP_INCLUDE_DIRS} )
    message(GST_RTSP_LIBRARY_DIRS: ${GST_RTSP_LIBRARY_DIRS} )
    message(GST_RTSP_LIBRARIES: ${GST_RTSP_LIBRARIES} )
    message(GST_SDP_INCLUDE_DIRS: ${GST_SDP_INCLUDE_DIRS} )
    message(GST_SDP_LIBRARY_DIRS: ${GST_SDP_LIBRARY_DIRS} )
    message(GST_SDP_LIBRARIES: ${GST_SDP_LIBRARIES} )
    message(GST_CHECK_INCLUDE_DIRS: ${GST_CHECK_INCLUDE_DIRS} )
    message(GST_CHECK_LIBRARY_DIRS: ${GST_CHECK_LIBRARY_DIRS} )
    message(GST_CHECK_LIBRARIES: ${GST_CHECK_LIBRARIES} )
    message(GST_RTP_INCLUDE_DIRS: ${GST_RTP_INCLUDE_DIRS} )
    message(GST_RTP_LIBRARY_DIRS: ${GST_RTP_LIBRARY_DIRS} )
    message(GST_RTP_LIBRARIES: ${GST_RTP_LIBRARIES} )
    INCLUDE_DIRECTORIES(${GST_INCLUDE_DIRS} ${GST_RTSP_SERVER_INCLUDE_DIRS} ${GST_CHECK_INCLUDE_DIRS} ${GST_RTP_INCLUDE_DIRS} ${GST_RTSP_INCLUDE_DIRS})
    LINK_LIBRARIES(${GST_LIBRARIES} ${GST_RTSP_SERVER_LIBRARIES} ${GST_CHECK_LIBRARIES} ${GST_RTP_LIBRARIES} ${GST_RTSP_LIBRARIES})
endif()



add_executable(test-mp4 test-mp4.cpp)
add_executable(check-rtsp-server check-rtsp-server.cpp)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
