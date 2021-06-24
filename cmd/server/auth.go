package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	redisutil "github.com/kthomas/go-redisutil"
	"github.com/provideplatform/pgrok/common"
	util "github.com/provideplatform/provide-go/common/util"
)

func authorizeBearerJWT(bearerToken []byte) (*time.Time, error) {
	token, err := jwt.Parse(string(bearerToken), func(_jwtToken *jwt.Token) (interface{}, error) {
		var kid *string
		if kidhdr, ok := _jwtToken.Header["kid"].(string); ok {
			kid = &kidhdr
		}

		publicKey, _, _, _ := util.ResolveJWTKeypair(kid)
		if publicKey == nil {
			msg := "failed to resolve a valid JWT verification key"
			if kid != nil {
				msg = fmt.Sprintf("%s; invalid kid specified in header: %s", msg, *kid)
			} else {
				msg = fmt.Sprintf("%s; no default verification key configured", msg)
			}
			return nil, fmt.Errorf(msg)
		}

		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims := token.Claims.(jwt.MapClaims)
	sub, subok := claims["sub"].(string)
	if !subok {
		return nil, errors.New("failed to parse bearer authorization subject")
	}

	// if non-nil and returned error is nil, tunnel will be closed upon expiration with a message
	// shown to the user containing instructions on how to increase subscription capacity
	var tunnelExpiration *time.Time

	tunnelsKey := strings.ReplaceAll(fmt.Sprintf("pgrok.tunnels.subscription.%s", sub), ":", ".")
	err = redisutil.WithRedlock(tunnelsKey, func() error {
		val, err := redisutil.Get(tunnelsKey)
		if err != nil {
			err = redisutil.Set(tunnelsKey, pgrokSubscriptionDefaultCapacity, nil)
			if err != nil {
				return err
			}
			val = common.StringOrNil(strconv.Itoa(pgrokSubscriptionDefaultCapacity))
		}

		intval, err := strconv.Atoi(*val)
		if err != nil {
			return err
		}

		capacity := int64(intval)

		if capacity > 0 {
			common.Log.Debugf("pgrok tunnels subscription for authorized subject %s has available capacity: %d", sub, capacity)
			cap, err := redisutil.Decrement(tunnelsKey)
			if err != nil {
				common.Log.Warningf("pgrok tunnels subscription for authorized subject %s failed to consume available subscription capacity", sub)
				return err
			}

			capacity = *cap
			common.Log.Debugf("pgrok tunnels subscription for authorized subject %s consumed available subscription capacity; %d concurrent tunnels remain available", sub, capacity)
		} else {
			exp := time.Now().Add(pgrokSubscriptionDefaultFreeTierTunnelDuration)
			common.Log.Debugf("pgrok tunnels subscription for authorized subject %s has no available capacity; free tier tunnel will expire at %s", sub, exp.String())
			tunnelExpiration = &exp // valid subject authorized but has no available subscription capacity; tunnel will operate on the free tier
		}

		return nil
	})

	if err != nil {
		common.Log.Warningf("pgrok tunnels subscription for authorized subject %s failed to consume available subscription capacity; distributed mutex not acquired; %s", sub, err.Error())
		return nil, err
	}

	common.Log.Debugf("pgrok tunnel connection presented valid bearer authorization credentials; authorized subject: %s", sub)
	return tunnelExpiration, nil
}
