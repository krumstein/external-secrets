/*
Copyright © The ESO Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package iam

import (
	"context"
	"testing"

	tassert "github.com/stretchr/testify/assert"
)

func TestBuildExchangeTokenRequest_FederatedServiceAccount(t *testing.T) {
	t.Parallel()

	exchanger := &GrpcTokenExchanger{}
	req, err := exchanger.buildExchangeTokenRequest(context.Background(), &TokenRequest{
		AuthType:     TokenAuthTypeFederatedServiceAccount,
		SubjectToken: "nebius-sa-id",
		ActorToken:   "k8s-jwt",
	})

	tassert.NoError(t, err)
	tassert.Equal(t, tokenExchangeGrantType, req.GetGrantType())
	tassert.Equal(t, accessTokenRequestedType, req.GetRequestedTokenType())
	tassert.Equal(t, "nebius-sa-id", req.GetSubjectToken())
	tassert.Equal(t, subjectIdentifierTokenType, req.GetSubjectTokenType())
	tassert.Equal(t, "k8s-jwt", req.GetActorToken())
	tassert.Equal(t, jwtSubjectTokenType, req.GetActorTokenType())
}

func TestBuildExchangeTokenRequest_FederatedServiceAccountRequiresSubjectToken(t *testing.T) {
	t.Parallel()

	exchanger := &GrpcTokenExchanger{}
	_, err := exchanger.buildExchangeTokenRequest(context.Background(), &TokenRequest{
		AuthType:   TokenAuthTypeFederatedServiceAccount,
		ActorToken: "k8s-jwt",
	})

	tassert.EqualError(t, err, errInvalidSubjectToken)
}

func TestBuildExchangeTokenRequest_FederatedServiceAccountRequiresActorToken(t *testing.T) {
	t.Parallel()

	exchanger := &GrpcTokenExchanger{}
	_, err := exchanger.buildExchangeTokenRequest(context.Background(), &TokenRequest{
		AuthType:     TokenAuthTypeFederatedServiceAccount,
		SubjectToken: "nebius-sa-id",
	})

	tassert.EqualError(t, err, errInvalidActorToken)
}
