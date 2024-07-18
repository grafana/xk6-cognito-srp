package cognito

//go package cognito srp
import (
	"context"
	"fmt"
	"time"

	cognitosrp "github.com/alexrudd/cognito-srp/v4.1.0"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"

	// "go.k6.io/k6/js/common"
	"go.k6.io/k6/js/modules"
)

// Register the extension on module initialization, available to
// import from JS as "k6/x/cognito".
func init() {
	fmt.Printf("Inside init")
	modules.Register("k6/x/cognito-srp", new(Cognito))
}

// Cognito is the k6 extension for a Cognito client.
type Cognito struct{}

// Client is the Cognito client wrapper.
type Client struct {
	// https://github.com/aws/aws-sdk-go-v2/blob/main/service/cognitoidentityprovider/api_client.go
	client *cip.Client
}
type keyValue map[string]interface{}

type AuthOptionalParams struct {
	// https://stackoverflow.com/questions/2032149/optional-parameters-in-go
	clientMetadata map[string]string
	cognitoSecret  *string
}

func contains(array []string, element string) bool {
	fmt.Printf("Inside contains")
	for _, item := range array {
		if item == element {
			return true
		}
	}
	return false
}

func (r *Cognito) Connect(region string) (*Client, error) {

	fmt.Printf("Inside Connect", region)

	regionAws := config.WithRegion(region)
	//cred := config.WithCredentialsProvider(aws.AnonymousCredentials{})

	// configure cognito identity provider
	// https://github.com/aws/aws-sdk-go-v2
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		regionAws,
	)

	if err != nil {
		return nil, err
	}

	client := Client{
		client: cip.NewFromConfig(cfg),
	}

	return &client, nil
}

func (c *Client) Auth(username, password, poolId, clientId string, params AuthOptionalParams) (keyValue, error) {
    if username == "" || password == "" || poolId == "" || clientId == "" {
        return nil, fmt.Errorf("All parameters (username, password, poolId, clientId) must be non-empty")
    }

    csrp, err := cognitosrp.NewCognitoSRP(username, password, poolId, clientId, params.cognitoSecret)
    if err != nil {
        return nil, fmt.Errorf("Failed to initialize CognitoSRP: %w", err)
    }

	// initiate auth
	resp, err := c.client.InitiateAuth(context.TODO(), &cip.InitiateAuthInput{
		AuthFlow:       types.AuthFlowTypeUserSrpAuth,
		ClientId:       aws.String(csrp.GetClientId()),
		AuthParameters: csrp.GetAuthParams(),
		ClientMetadata: params.clientMetadata,
	})

	if err != nil {
		return nil, err
	}

	// respond to password verifier challenge
	if resp.ChallengeName == types.ChallengeNameTypePasswordVerifier {
		challengeResponses, err := csrp.PasswordVerifierChallenge(resp.ChallengeParameters, time.Now())

		if err != nil {
			return nil, err
		}

		resp, err := c.client.RespondToAuthChallenge(context.TODO(), &cip.RespondToAuthChallengeInput{
			ChallengeName:      types.ChallengeNameTypePasswordVerifier,
			ChallengeResponses: challengeResponses,
			ClientId:           aws.String(csrp.GetClientId()),
		})
		if err != nil {
			return nil, err
		}

		// data := make(keyValue, 3)

		data := keyValue{
			"AccessToken":  *resp.AuthenticationResult.AccessToken,
			"IdToken":      *resp.AuthenticationResult.IdToken,
			"RefreshToken": *resp.AuthenticationResult.RefreshToken,
		}

		// data["AccessToken"] := *resp.AuthenticationResult.AccessToken
		// data["IdToken"] := *resp.AuthenticationResult.IdToken
		// data["RefreshToken"] := *resp.AuthenticationResult.RefreshToken

		return data, nil

	} else {
		// other challenges await...
		return nil, fmt.Errorf("Challenge %s is not supported", resp.ChallengeName)
	}

}
