package httpserver

import (
	"log"
	"net/http"
	"strconv"
	"sync"

	"acmeProject/acmeclient"

	"github.com/gin-gonic/gin"
)

const (
	port int = 5002
)

type HttpChallengeServer struct {
	challenges      map[string]string
	challengeLocker sync.RWMutex
	server          *http.Server
	ctx             *acmeclient.Context
}

func StartHttpChallengeServer(context *acmeclient.Context) {
	httpChallengeServer := &HttpChallengeServer{
		challenges: make(map[string]string),
		ctx:        context,
	}
	go httpChallengeServer.ListenForChallenges()
	go httpChallengeServer.InitializeHttpServer()
}

func (httpChallengeServer *HttpChallengeServer) InitializeHttpServer() {
	httpChallengeServer.server = &http.Server{
		Addr:    ":" + strconv.Itoa(port),
		Handler: httpChallengeServer.getConfiguredHTTPRouter(),
	}
	log.Println("[HTTP Challenge Server] Starting HTTP Challenge Server at port", port)
	err := httpChallengeServer.server.ListenAndServe()
	if err != nil {
		log.Fatalf("[HTTP Challenge Server] Failed to set challenge server %s\n", err.Error())
	}
}

func (httpChallengeServer *HttpChallengeServer) handleChallengeRequest() gin.HandlerFunc {
	return func(c *gin.Context) {
		challengeToken := c.Param("challengeToken")
		response, ok := httpChallengeServer.getResponse(challengeToken)
		if !ok {
			log.Println("[HTTP Challenge Server] Failed to respond to request for", challengeToken)
			c.JSON(http.StatusNotFound, gin.H{"error": "could not find challenge"})
		} else {
			log.Println("[HTTP Challenge Server] Responded to request for", challengeToken)
			c.Data(http.StatusOK, "application/octet-stream", []byte(response))
		}
	}
}

func (httpChallengeServer *HttpChallengeServer) getConfiguredHTTPRouter() *gin.Engine {

	router := gin.New()
	router.Use(gin.Recovery())
	router.GET("/.well-known/acme-challenge/:challengeToken", httpChallengeServer.handleChallengeRequest())
	return router
}

func (httpChallengeServer *HttpChallengeServer) ListenForChallenges() {
	for challenge := range httpChallengeServer.ctx.HttpChallengeChannel {
		httpChallengeServer.addChallenge(&challenge)
	}
}

//ADDChallenge to challenge map
func (httpChallengeServer *HttpChallengeServer) addChallenge(challenge *acmeclient.HTTPChallenge) {
	httpChallengeServer.challengeLocker.Lock()
	defer httpChallengeServer.challengeLocker.Unlock()

	httpChallengeServer.challenges[challenge.URLParam] = challenge.Response
}

//getTXT from stores challenge map and remove entry
func (httpChallengeServer *HttpChallengeServer) getResponse(challengeToken string) (string, bool) {
	httpChallengeServer.challengeLocker.RLock()
	defer httpChallengeServer.challengeLocker.RUnlock()
	resp, ok := httpChallengeServer.challenges[challengeToken]

	return resp, ok
}
