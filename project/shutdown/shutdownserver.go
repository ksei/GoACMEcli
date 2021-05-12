package shutdown

import (
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

const (
	port int = 5003
)

type ShutdownServer struct {
	server *http.Server
}

func StartShutdownServer() {
	shutdownServer := &ShutdownServer{}
	shutdownServer.InitializeShutdownServer()
}

func (shutdownServer *ShutdownServer) InitializeShutdownServer() {
	shutdownServer.server = &http.Server{
		Addr:    ":" + strconv.Itoa(port),
		Handler: shutdownServer.getConfiguredHTTPRouter(),
	}
	log.Println("[HTTP Shutdown Server] Starting HTTP Shutdown Server at port", port)
	err := shutdownServer.server.ListenAndServe()
	if err != nil {
		log.Fatalf("[HTTP Shutdown Server] Listening interruped %s\n", err.Error())
	}
}

func (shutdownServer *ShutdownServer) getConfiguredHTTPRouter() *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())
	router.GET("/shutdown", func(c *gin.Context) {
		c.String(http.StatusOK, "If you made it here, bye bye.")
		shutdownServer.server.Shutdown(c)
	})

	return router
}
