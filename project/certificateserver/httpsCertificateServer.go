package certificateserver

import (
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

const (
	port            int    = 5001
	certificatePath string = "tls/certificate.pem"
	privateKeyPath  string = "tls/private_key.pem"
)

type HttpsCertificateServer struct {
	server *http.Server
}

func StartHttpsCertificateServer() {
	certificateServer := &HttpsCertificateServer{}
	go certificateServer.InitializeHttpServer()
}

func (certificateServer *HttpsCertificateServer) InitializeHttpServer() {
	certificateServer.server = &http.Server{
		Addr:    ":" + strconv.Itoa(port),
		Handler: certificateServer.getConfiguredHTTPRouter(),
	}
	log.Println("[HTTPS Certificate Server] Starting HTTPS Certificate Server at port", port)
	err := certificateServer.server.ListenAndServeTLS(certificatePath, privateKeyPath)
	if err != nil {
		log.Fatalf("[HTTPS Certificate Server] Failed to set certificate server %s\n", err.Error())
	}
}

func (certificateServer *HttpsCertificateServer) getConfiguredHTTPRouter() *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "If you made it here, I deserve full points.")
	})

	return router
}
