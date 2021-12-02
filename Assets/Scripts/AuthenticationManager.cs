using UnityEngine;
using System.Collections.Generic;
using Amazon.Extensions.CognitoAuthentication;
using Amazon.CognitoIdentity;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using System;
using System.Threading.Tasks;
using System.Net;

public class AuthenticationManager : MonoBehaviour
{
   // the AWS region of where your services live
   public static Amazon.RegionEndpoint Region = Amazon.RegionEndpoint.USEast2;

    // In production, should probably keep these in a config file
    //const string IdentityPool = "YOUR_IDENTITY_POOL_ID"; //insert your Cognito User Pool ID, found under General Settings
    //const string AppClientID = "YOUR_APP_CLIENT_ID"; //insert App client ID, found under App Client Settings
    //const string userPoolId = "YOUR_USER_POOL_ID";

    //const string IdentityPool = "us-east-2:f0a37633-5b6d-4dba-b14f-e9af8c9d01c9"; //insert your Cognito User Pool ID, found under General Settings
    //const string AppClientID = "2mkgn63cpl16m5aef3fr5ltmpd"; //insert App client ID, found under App Client Settings
    //const string userPoolId = "us-east-2_EcwA0QhFR";


    //PASSWORDLESS AUTH
    //const string IdentityPool = "us-east-2:f0a37633-5b6d-4dba-b14f-e9af8c9d01c9"; //insert your Cognito User Pool ID, found under General Settings
    //const string AppClientID = "6sflqugl8en25p1ujoaq3fimnr"; //insert App client ID, found under App Client Settings
    //const string userPoolId = "us-east-2_jb5OLMPNl";

    //PASSWORDLESS AUTH USERNAME
    const string IdentityPool = "us-east-2:f0a37633-5b6d-4dba-b14f-e9af8c9d01c9"; //insert your Cognito User Pool ID, found under General Settings
    const string AppClientID = "65c40n1g4o6au937aflpifb2ke"; //insert App client ID, found under App Client Settings
    const string userPoolId = "us-east-2_tdKc75vhX";

    private AmazonCognitoIdentityProviderClient _provider;
   private CognitoAWSCredentials _cognitoAWSCredentials;
   private static string _userid = "";
   private CognitoUser _user;

    #region blug
    //public async Task<bool> RefreshSession()
    //{
    //   Debug.Log("RefreshSession");

    //   DateTime issued = DateTime.Now;
    //   UserSessionCache userSessionCache = new UserSessionCache();
    //   SaveDataManager.LoadJsonData(userSessionCache);

    //   if (userSessionCache != null && userSessionCache._refreshToken != null && userSessionCache._refreshToken != "")
    //   {
    //   try
    //   {
    //      CognitoUserPool userPool = new CognitoUserPool(userPoolId, AppClientID, _provider);

    //      // apparently the username field can be left blank for a token refresh request
    //      CognitoUser user = new CognitoUser("", AppClientID, userPool, _provider);

    //      // The "Refresh token expiration (days)" (Cognito->UserPool->General Settings->App clients->Show Details) is the
    //      // amount of time since the last login that you can use the refresh token to get new tokens. After that period the refresh
    //      // will fail Using DateTime.Now.AddHours(1) is a workaround for https://github.com/aws/aws-sdk-net-extensions-cognito/issues/24
    //      user.SessionTokens = new CognitoUserSession(
    //         userSessionCache.getIdToken(),
    //         userSessionCache.getAccessToken(),
    //         userSessionCache.getRefreshToken(),
    //         issued,
    //         DateTime.Now.AddDays(30)); // TODO: need to investigate further. 
    //                                    // It was my understanding that this should be set to when your refresh token expires...

    //      // Attempt refresh token call
    //      AuthFlowResponse authFlowResponse = await user.StartWithRefreshTokenAuthAsync(new InitiateRefreshTokenAuthRequest
    //      {
    //         AuthFlowType = AuthFlowType.REFRESH_TOKEN_AUTH
    //      })
    //      .ConfigureAwait(false);

    //      // Debug.Log("User Access Token after refresh: " + token);
    //      Debug.Log("User refresh token successfully updated!");

    //      // update session cache
    //      UserSessionCache userSessionCacheToUpdate = new UserSessionCache(
    //         authFlowResponse.AuthenticationResult.IdToken,
    //         authFlowResponse.AuthenticationResult.AccessToken,
    //         authFlowResponse.AuthenticationResult.RefreshToken,
    //         userSessionCache.getUserId());

    //      SaveDataManager.SaveJsonData(userSessionCacheToUpdate);

    //      // update credentials with the latest access token
    //      _cognitoAWSCredentials = user.GetCognitoAWSCredentials(IdentityPool, Region);

    //      _user = user;

    //      return true;
    //   }
    //   catch (NotAuthorizedException ne)
    //   {
    //      // https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html
    //      // refresh tokens will expire - user must login manually every x days (see user pool -> app clients -> details)
    //      Debug.Log("NotAuthorizedException: " + ne);
    //   }
    //   catch (WebException webEx)
    //   {
    //      // we get a web exception when we cant connect to aws - means we are offline
    //      Debug.Log("WebException: " + webEx);
    //   }
    //   catch (Exception ex)
    //   {
    //      Debug.Log("Exception: " + ex);
    //   }
    //   }
    //   return false;
    //}

    //public async Task<bool> Login(string email, string password)
    //{
    //    Debug.Log("Login: " + email + ", " + password);

    //   CognitoUserPool userPool = new CognitoUserPool(userPoolId, AppClientID, _provider);
    //   CognitoUser user = new CognitoUser(email, AppClientID, userPool, _provider);

    //   InitiateSrpAuthRequest authRequest = new InitiateSrpAuthRequest()
    //   {
    //      Password = password
    //   };

    //   try
    //   {
    //      AuthFlowResponse authFlowResponse = await user.StartWithSrpAuthAsync(authRequest).ConfigureAwait(false);

    //      _userid = await GetUserIdFromProvider(authFlowResponse.AuthenticationResult.AccessToken);
    //       Debug.Log("Users unique ID from cognito: " + _userid);

    //         UserSessionCache userSessionCache = new UserSessionCache(
    //         authFlowResponse.AuthenticationResult.IdToken,
    //         authFlowResponse.AuthenticationResult.AccessToken,
    //         authFlowResponse.AuthenticationResult.RefreshToken,
    //         _userid);

    //      SaveDataManager.SaveJsonData(userSessionCache);

    //      // This how you get credentials to use for accessing other services.
    //      // This IdentityPool is your Authorization, so if you tried to access using an
    //      // IdentityPool that didn't have the policy to access your target AWS service, it would fail.
    //      _cognitoAWSCredentials = user.GetCognitoAWSCredentials(IdentityPool, Region);

    //      _user = user;

    //      return true;
    //   }
    //   catch (Exception e)
    //   {
    //      Debug.Log("Login failed, exception: " + e);
    //      return false;
    //   }
    //}
    #endregion

    public async Task<bool> Login(string userName, string password)
    {
        Debug.Log("Login: " + userName + ", " + password);

        CognitoUserPool userPool = new CognitoUserPool(userPoolId, AppClientID, _provider);
        CognitoUser user = new CognitoUser(userName, AppClientID, userPool, _provider);

        InitiateCustomAuthRequest authRequest = new InitiateCustomAuthRequest()
        {
            AuthParameters = new Dictionary<string, string>()
            {
                { "USERNAME",userName}
            },
            ClientMetadata = new Dictionary<string, string>()
            {
                { "USERNAME",userName}
            }
        };

        string accessToken;

        try
        {
            AuthFlowResponse authResponse = await user.StartWithCustomAuthAsync(authRequest).ConfigureAwait(false);

            while (authResponse.AuthenticationResult == null)
            {
                if (authResponse.ChallengeName == ChallengeNameType.CUSTOM_CHALLENGE)
                {
                    Debug.Log("We are a custom challenge");
                    Debug.Log("session id " + authResponse.SessionID);
                    Debug.Log("challengeName " + authResponse.ChallengeName);


                    PrintDict(authResponse.ChallengeParameters, "Challenge Parameters:");
                    PrintDict(authResponse.ClientMetadata, "Client Metadata");


                    authResponse = await user.RespondToCustomAuthAsync(new RespondToCustomChallengeRequest()
                    {
                        SessionID = authResponse.SessionID,
                        ChallengeParameters = new Dictionary<string, string>()
                        {
                            { "ANSWER","opensesame"},
                            //{ "USERNAME",  authResponse.ChallengeParameters["USERNAME"]}
                            { "USERNAME", userName }
                        }

                    });

                    accessToken = authResponse.AuthenticationResult.AccessToken;
                    Debug.Log("Access Token " + accessToken);
                    Debug.Log("Refresh Token " + authResponse.AuthenticationResult.RefreshToken);
                    Debug.Log(" Token " + authResponse.AuthenticationResult.IdToken);
                } else
                {
                    Debug.Log("Unrecognized authentication challenge.");
                    accessToken = "";
                    break;
                }
            }

            if (authResponse.AuthenticationResult != null)
            {
                Debug.Log("User successfully authenticated.");
                return true;
            } else
            {
                Debug.Log("Error in authentication process.");
                return false;
            }
        }
        catch (Exception e)
        {
            Debug.Log("Login failed, exception: " + e + " " + e.StackTrace + " ");
            return false;
        }
    }

    private void PrintDict(IDictionary<string, string> dict, string header)
    {
        foreach (KeyValuePair<string, string> kvp in dict)
        {
            //textBox3.Text += ("Key = {0}, Value = {1}", kvp.Key, kvp.Value);
            Debug.Log(header + $" Key = {kvp.Key}, Value = { kvp.Value}");
        }
    }

    public async Task<bool> Signup(string username, string password)
   {
       Debug.Log("SignUpRequest: " + username + ", " + ", " + password);

        SignUpRequest signUpRequest = new SignUpRequest()
      {
         ClientId = AppClientID,
         Username = username,
         Password = password
      };

      // must provide all attributes required by the User Pool that you configured
      List<AttributeType> attributes = new List<AttributeType>()
      {

      };
      signUpRequest.UserAttributes = attributes;

      try
      {
         SignUpResponse sighupResponse = await _provider.SignUpAsync(signUpRequest);
         Debug.Log("Sign up successful");
         return true;
      }
      catch (Exception e)
      {
         Debug.Log("Sign up failed, exception: " + e);
         return false;
      }
   }

   // Make the user's unique id available for GameLift APIs, linking saved data to user, etc
   public string GetUsersId()
   {
      // Debug.Log("GetUserId: [" + _userid + "]");
      if (_userid == null || _userid == "")
      {
         // load userid from cached session 
         UserSessionCache userSessionCache = new UserSessionCache();
         SaveDataManager.LoadJsonData(userSessionCache);
         _userid = userSessionCache.getUserId();
      }
      return _userid;
   }

   // we call this once after the user is authenticated, then cache it as part of the session for later retrieval 
   private async Task<string> GetUserIdFromProvider(string accessToken)
   {
      // Debug.Log("Getting user's id...");
      string subId = "";

      Task<GetUserResponse> responseTask =
         _provider.GetUserAsync(new GetUserRequest
         {
            AccessToken = accessToken
         });

      GetUserResponse responseObject = await responseTask;

      // set the user id
      foreach (var attribute in responseObject.UserAttributes)
      {
         if (attribute.Name == "sub")
         {
            subId = attribute.Value;
            break;
         }
      }

      return subId;
   }

   // Limitation note: so this GlobalSignOutAsync signs out the user from ALL devices, and not just the game.
   // So if you had other sessions for your website or app, those would also be killed.  
   // Currently, I don't think there is native support for granular session invalidation without some work arounds.
   public async void SignOut()
   {
      await _user.GlobalSignOutAsync();

      // Important! Make sure to remove the local stored tokens 
      UserSessionCache userSessionCache = new UserSessionCache("", "", "", "");
      SaveDataManager.SaveJsonData(userSessionCache);

      Debug.Log("user logged out.");
   }

   // access to the user's authenticated credentials to be used to call other AWS APIs
   public CognitoAWSCredentials GetCredentials()
   {
      return _cognitoAWSCredentials;
   }

   // access to the user's access token to be used wherever needed - may not need this at all.
   public string GetAccessToken()
   {
      UserSessionCache userSessionCache = new UserSessionCache();
      SaveDataManager.LoadJsonData(userSessionCache);
      return userSessionCache.getAccessToken();
   }

   void Awake()
   {
      Debug.Log("AuthenticationManager: Awake");
      _provider = new AmazonCognitoIdentityProviderClient(new Amazon.Runtime.AnonymousAWSCredentials(), Region);
   }
}
