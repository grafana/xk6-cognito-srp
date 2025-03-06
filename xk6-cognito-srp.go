package cognito

import (
	"context"
	"fmt"
	"log"
	"time"

	cognitosrp "github.com/alexrudd/cognito-srp/v4"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"go.k6.io/k6/js/modules"
)

// Register the extension on module initialization, available to
// import from JS as "k6/x/cognito-srp".
func init() {
	log.Printf("DEBUG: Inside init")
	modules.Register("k6/x/cognito-srp", new(Cognito))
}

// Cognito is the k6 extension for a Cognito client.
type Cognito struct{}

// Client is the Cognito client wrapper.
type Client struct {
	client *cip.Client
}

type keyValue map[string]interface{}

type AuthOptionalParams struct {
	clientMetadata map[string]string
	cognitoSecret  *string
}

func contains(array []string, element string) bool {
	log.Printf("DEBUG: Inside contains")
	for _, item := range array {
		if item == element {
			return true
		}
	}
	return false
}

func (r *Cognito) Connect(region string) (*Client, error) {
	// Log the region being used for connection.
	log.Printf("DEBUG: Inside Connect: %s", region)

	regionAws := config.WithRegion(region)

	// Load AWS configuration.
	cfg, err := config.LoadDefaultConfig(context.TODO(), regionAws)
	if err != nil {
		return nil, err
	}

	client := Client{
		client: cip.NewFromConfig(cfg),
	}

	return &client, nil
}

func (c *Client) Auth(username string, password string, poolId string, clientId string, params AuthOptionalParams) (keyValue, error) {
	// Configure Cognito SRP; check for errors during creation.
	csrp, err := cognitosrp.NewCognitoSRP(username, password, poolId, clientId, params.cognitoSecret)
	if err != nil {
		return nil, err
	}

	// Initiate authentication.
	resp, err := c.client.InitiateAuth(context.TODO(), &cip.InitiateAuthInput{
		AuthFlow:       types.AuthFlowTypeUserSrpAuth,
		ClientId:       aws.String(csrp.GetClientId()),
		AuthParameters: csrp.GetAuthParams(),
		ClientMetadata: params.clientMetadata,
	})
	if err != nil {
		return nil, err
	}

	// Respond to password verifier challenge.
	if resp.ChallengeName == types.ChallengeNameTypePasswordVerifier {
		challengeResponses, err := csrp.PasswordVerifierChallenge(resp.ChallengeParameters, time.Now())
		if err != nil {
			return nil, err
		}

		resp, err = c.client.RespondToAuthChallenge(context.TODO(), &cip.RespondToAuthChallengeInput{
			ChallengeName:      types.ChallengeNameTypePasswordVerifier,
			ChallengeResponses: challengeResponses,
			ClientId:           aws.String(csrp.GetClientId()),
		})
		if err != nil {
			return nil, err
		}

		data := keyValue{
			"AccessToken":  *resp.AuthenticationResult.AccessToken,
			"IdToken":      *resp.AuthenticationResult.IdToken,
			"RefreshToken": *resp.AuthenticationResult.RefreshToken,
		}

		return data, nil
	} else {
		return nil, fmt.Errorf("Challenge %s is not supported", resp.ChallengeName)
	}
}
