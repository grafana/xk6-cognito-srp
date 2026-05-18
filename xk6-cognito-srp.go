// Package cognito provides AWS Cognito SRP authentication for k6 scripts.
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

func init() {
	log.Printf("DEBUG: Inside init")
	modules.Register("k6/x/cognito-srp", new(Cognito))
}

// Cognito is the module's root object, exposed to JS as `k6/x/cognito-srp`.
type Cognito struct{}

// Client wraps an AWS Cognito Identity Provider client.
type Client struct {
	client *cip.Client
}

// KeyValue is a JS-friendly map of the tokens returned by Auth.
type KeyValue map[string]any

// AuthOptionalParams holds optional parameters for the Auth call.
// All fields are unexported and will need setters before they can be populated from JS.
type AuthOptionalParams struct {
	clientMetadata map[string]string
	cognitoSecret  *string
	mfaCode        string
}

// Connect returns a Client configured for the given AWS region.
func (r *Cognito) Connect(region string) (*Client, error) {
	log.Printf("DEBUG: Connecting to Cognito in region: %s", region)

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return nil, err
	}

	client := Client{
		client: cip.NewFromConfig(cfg),
	}

	return &client, nil
}

// Auth performs the USER_SRP_AUTH flow and returns the AccessToken, IdToken,
// and RefreshToken on success.
func (c *Client) Auth(username, password, poolID, clientID string, params AuthOptionalParams) (KeyValue, error) {
	csrp, err := cognitosrp.NewCognitoSRP(username, password, poolID, clientID, params.cognitoSecret)
	if err != nil {
		return nil, err
	}

	initiateResp, err := c.client.InitiateAuth(context.TODO(), &cip.InitiateAuthInput{
		AuthFlow:       types.AuthFlowTypeUserSrpAuth,
		ClientId:       aws.String(csrp.GetClientId()),
		AuthParameters: csrp.GetAuthParams(),
		ClientMetadata: params.clientMetadata,
	})
	if err != nil {
		return nil, err
	}

	// Handle authentication challenges
	switch initiateResp.ChallengeName {
	case types.ChallengeNameTypePasswordVerifier:
		return c.handlePasswordVerifierChallenge(initiateResp, csrp, clientID, params)

	case types.ChallengeNameTypeSmsMfa:
		// Handle MFA Challenge
		if params.mfaCode == "" {
			return nil, fmt.Errorf("MFA required but no code provided")
		}
		return c.handleMFAChallenge(*initiateResp.Session, params.mfaCode, clientID)

	default:
		return nil, fmt.Errorf("unsupported challenge: %s", initiateResp.ChallengeName)
	}
}

func (c *Client) handlePasswordVerifierChallenge(
	resp *cip.InitiateAuthOutput,
	csrp *cognitosrp.CognitoSRP,
	clientID string,
	params AuthOptionalParams,
) (KeyValue, error) {
	challengeResponses, err := csrp.PasswordVerifierChallenge(resp.ChallengeParameters, time.Now())
	if err != nil {
		return nil, err
	}

	challengeResp, err := c.client.RespondToAuthChallenge(context.TODO(), &cip.RespondToAuthChallengeInput{
		ChallengeName:      types.ChallengeNameTypePasswordVerifier,
		ChallengeResponses: challengeResponses,
		ClientId:           aws.String(clientID),
		Session:            resp.Session, // Ensure session is passed for next step (MFA)
	})
	if err != nil {
		return nil, err
	}

	// If MFA is required
	if challengeResp.ChallengeName == types.ChallengeNameTypeSmsMfa {
		if params.mfaCode == "" {
			return nil, fmt.Errorf("MFA required but no code provided")
		}
		return c.handleMFAChallenge(*challengeResp.Session, params.mfaCode, clientID)
	}

	return extractTokens(challengeResp), nil
}

func (c *Client) handleMFAChallenge(session, mfaCode, clientID string) (KeyValue, error) {
	log.Printf("DEBUG: Responding to MFA challenge")

	mfaResp, err := c.client.RespondToAuthChallenge(context.TODO(), &cip.RespondToAuthChallengeInput{
		ChallengeName: types.ChallengeNameTypeSmsMfa,
		ChallengeResponses: map[string]string{
			"USERNAME":     session, // Ensure this is correct
			"SMS_MFA_CODE": mfaCode,
		},
		ClientId: aws.String(clientID),
		Session:  aws.String(session),
	})
	if err != nil {
		return nil, err
	}

	return extractTokens(mfaResp), nil
}

func extractTokens(resp *cip.RespondToAuthChallengeOutput) KeyValue {
	return KeyValue{
		"AccessToken":  *resp.AuthenticationResult.AccessToken,
		"IdToken":      *resp.AuthenticationResult.IdToken,
		"RefreshToken": *resp.AuthenticationResult.RefreshToken,
	}
}
