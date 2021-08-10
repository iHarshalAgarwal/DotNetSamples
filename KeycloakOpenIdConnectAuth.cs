using System;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

[assembly: OwinStartup( typeof( Web.Startup.Startup ) )]
namespace Web.Startup
{
	public class Startup
	{
		private readonly string _keyCloakAuthUrl = ConfigurationManager.AppSettings["KeycloakAuthUrl"];
		private readonly string _clientId = ConfigurationManager.AppSettings["KeycloakClientId"];
		private readonly string _clientSecret = ConfigurationManager.AppSettings["KeycloakClientSecret"];
		// you can use CryptoRandom.CreateUniqueId( 32 ) to create "_codeVerifier" text
		private readonly string _codeVerifier = ConfigurationManager.AppSettings["KeycloakCodeVerifier"];

		public void Configuration( IAppBuilder app )
		{
			app.UseCookieAuthentication( new CookieAuthenticationOptions {
				AuthenticationType = OpenIdConnectAuthenticationDefaults.AuthenticationType
			} );

			app.UseOpenIdConnectAuthentication( new OpenIdConnectAuthenticationOptions {
				ClientId = _clientId,
				ClientSecret = _clientSecret,
				Authority = _keyCloakAuthUrl,
				ResponseType = OpenIdConnectResponseType.Code,
				Scope = OpenIdConnectScope.OpenIdProfile,
				UsePkce = true,
				SignInAsAuthenticationType = OpenIdConnectAuthenticationDefaults.AuthenticationType,
				Notifications = new OpenIdConnectAuthenticationNotifications {
					AuthorizationCodeReceived = ValidateTokenAndSetClaims,
					AuthenticationFailed = OnAuthenticationFailed,
					RedirectToIdentityProvider = SetRequestParameters,
				},
			} );
		}

		private Task SetRequestParameters( RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context )
		{
			if (context.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication) {
				// this is required for PKCE
				string codeChallenge;
				using (var sha256 = SHA256.Create()) {
					var challengeBytes = sha256.ComputeHash( Encoding.UTF8.GetBytes( _codeVerifier ) );
					codeChallenge = Base64Url.Encode( challengeBytes );
				}

				// set code_challenge parameter on authorization request
				context.ProtocolMessage.SetParameter( "code_challenge", codeChallenge );
				context.ProtocolMessage.SetParameter( "code_challenge_method", "S256" );
			}

			// this will set dynamic redirect uri
			context.ProtocolMessage.RedirectUri = context.Request.Uri.AbsoluteUri;

			return Task.CompletedTask;
		}

		private Task ValidateTokenAndSetClaims( AuthorizationCodeReceivedNotification context )
		{
			// this is to handle when user refreshes the browser immediate after a successful authentication
			if (((ClaimsPrincipal)HttpContext.Current.User).Identities.First().NameClaimType == "preferred_username") {
				return Task.CompletedTask;
			}

			var client = new HttpClient();

			var codeTokenAsync = client.RequestAuthorizationCodeTokenAsync( new AuthorizationCodeTokenRequest {
				Address = $"{_keyCloakAuthUrl}/protocol/openid-connect/token",
				ClientId = _clientId,
				ClientSecret = _clientSecret,
				Code = context.Code,
				RedirectUri = context.Request.Uri.AbsoluteUri,
				CodeVerifier = _codeVerifier
			} );

			var tokenResponse = codeTokenAsync.GetAwaiter().GetResult();
			if (tokenResponse.IsError) {
				throw new Exception( tokenResponse.Raw );
			}

			var userInfoAsync = client.GetUserInfoAsync( new UserInfoRequest {
				Address = $"{_keyCloakAuthUrl}/protocol/openid-connect/userinfo",
				Token = tokenResponse.AccessToken
			} );

			var userInfo = userInfoAsync.GetAwaiter().GetResult();
			if (userInfo.IsError) {
				throw new Exception( tokenResponse.Raw );
			}

			var claims = userInfo.Claims;

			context.AuthenticationTicket = new AuthenticationTicket(
				new ClaimsIdentity(
					HttpContext.Current.User.Identity,
					claims,
					OpenIdConnectAuthenticationDefaults.AuthenticationType,
					"preferred_username",
					((ClaimsPrincipal)HttpContext.Current.User).Identities.First().RoleClaimType
				),
				new AuthenticationProperties()
			);

			return Task.CompletedTask;
		}

		private Task OnAuthenticationFailed( AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context )
		{
			context.HandleResponse();
			context.Response.Write( "Something went wrong." );

			return Task.CompletedTask;
		}
	}
}
