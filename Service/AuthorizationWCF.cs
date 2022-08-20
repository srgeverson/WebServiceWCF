using AppClassLibraryClient.model;
using AppClassLibraryDomain.model;
using AppClassLibraryDomain.service;
using JWT;
using JWT.Algorithms;
using JWT.Exceptions;
using JWT.Serializers;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Reflection;
using System.ServiceModel.Web;
using BCryptNet = BCrypt.Net.BCrypt;

namespace WebServiceWCF.Service
{
    public class AuthorizationWCF
    {
        private static string SECRET = ConfigurationManager.AppSettings["secret"];
        private static string EXPIRED = ConfigurationManager.AppSettings["expired"];
        private static string TOKEN_TYPE = ConfigurationManager.AppSettings["token"];

        public UsuarioLogado gerarToken(Usuario usuario, UsuarioLogin usuarioLogin, PermissaoService permissaoService)
        {
            if (usuario == null)
                throw new WebFaultException<TokenValidado>(new TokenValidado() { StatusCode = 404, Mensagem = "Não foi encontrado usuário vinculado ao e-mail informado!" }, HttpStatusCode.NotFound);
            try
            {
                if (!BCryptNet.Verify(usuarioLogin.senha, usuario.Senha)) throw new Exception("Senha inválida!");

                if (string.IsNullOrEmpty(SECRET)) throw new Exception("Não foi encontrado a chave secreta de validação do token.");
                if (string.IsNullOrEmpty(EXPIRED)) throw new Exception("Não foi definido tempo de validação do token.");
                if (string.IsNullOrEmpty(TOKEN_TYPE)) throw new Exception("Não foi definido tipo do token.");

                int[] permissoesId = permissaoService.PermissoesPorEmail(usuarioLogin.login)
                    .Select(permissao => permissao.Id)
                    .ToList()
                    .ConvertAll(x => x.Value)
                    .ToArray();
                var utcNow = DateTimeOffset.UtcNow;
                var extraHeaders = new Dictionary<string, object> { };
                var payload = new PayloadToken()
                {
                    sub = usuario.Id,
                    iss = Assembly.GetExecutingAssembly().GetName().Name,
                    roles = permissoesId,
                    name = usuario.Nome,
                    iat = utcNow.ToUnixTimeSeconds(),
                    exp = utcNow.AddSeconds(Convert.ToDouble(EXPIRED)).ToUnixTimeSeconds(),
                    aud = "AppGenérico"
                };
                var key = Convert.FromBase64String(SECRET);
                IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
                IJsonSerializer serializer = new JsonNetSerializer();
                IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
                IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
                var token = encoder.Encode(extraHeaders, payload, key);

                return new UsuarioLogado() {
                    token_type = TOKEN_TYPE,
                    access_token = token,
                    expires_in = utcNow.AddSeconds(Convert.ToDouble(EXPIRED)).ToUnixTimeSeconds(),
                    Mensagem = "Usuário autorizado" };
            }
            catch (Exception ex)
            {
                throw new WebFaultException<TokenValidado>(new TokenValidado() { StatusCode = 401, Mensagem = ex.Message }, HttpStatusCode.Unauthorized);
            }
        }

        public TokenValidado validarToken(IncomingWebRequestContext request)
        {
            try
            {
                string token = ExtrairToken(request);

                IJsonSerializer serializer = new JsonNetSerializer();
                var provider = new UtcDateTimeProvider();
                IJwtValidator validator = new JwtValidator(serializer, provider);
                IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
                IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
                IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);
                var key = Convert.FromBase64String(SECRET);
                return new TokenValidado()
                {
                    StatusCode = 200,
                    Mensagem = string.IsNullOrEmpty(decoder.Decode(token, key, verify: true)) ? string.Empty : "Token válido!"
                };
            }
            catch (TokenNotYetValidException tnyvex)
            {
                throw new WebFaultException<TokenValidado>(new TokenValidado() { StatusCode = 401, Mensagem = tnyvex.Message }, HttpStatusCode.Unauthorized);
            }
            catch (TokenExpiredException teex)
            {
                throw new WebFaultException<TokenValidado>(new TokenValidado() { StatusCode = 401, Mensagem = teex.Message }, HttpStatusCode.Unauthorized);
            }
            catch (SignatureVerificationException svex)
            {
                throw new WebFaultException<TokenValidado>(new TokenValidado() { StatusCode = 401, Mensagem = svex.Message }, HttpStatusCode.Unauthorized);
            }
            catch (Exception ex)
            {
                throw new WebFaultException<TokenValidado>(new TokenValidado() { StatusCode = 401, Mensagem = ex.Message }, HttpStatusCode.Unauthorized);
            }
        }

        public PayloadToken validarAcesso(IncomingWebRequestContext request, int[] roles)
        {
            try
            {
                string token = ExtrairToken(request);

                IJsonSerializer serializer = new JsonNetSerializer();
                var provider = new UtcDateTimeProvider();
                IJwtValidator validator = new JwtValidator(serializer, provider);
                IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
                IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
                IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);
                var key = Convert.FromBase64String(SECRET);
                var payloadToken = new JsonNetSerializer().Deserialize<PayloadToken>(decoder.Decode(token, key, verify: true));
                
                return payloadToken;
            }
            catch (TokenNotYetValidException tnyvex)
            {
                throw new WebFaultException<TokenValidado>(new TokenValidado() { StatusCode = 401, Mensagem = tnyvex.Message }, HttpStatusCode.Unauthorized);
            }
            catch (TokenExpiredException teex)
            {
                throw new WebFaultException<TokenValidado>(new TokenValidado() { StatusCode = 401, Mensagem = teex.Message }, HttpStatusCode.Unauthorized);
            }
            catch (SignatureVerificationException svex)
            {
                throw new WebFaultException<TokenValidado>(new TokenValidado() { StatusCode = 401, Mensagem = svex.Message }, HttpStatusCode.Unauthorized);
            }
            catch (Exception ex)
            {
                throw new WebFaultException<TokenValidado>(new TokenValidado() { StatusCode = 401, Mensagem = ex.Message }, HttpStatusCode.Unauthorized);
            }
        }

        private string ExtrairToken(IncomingWebRequestContext request)
        {
            try
            {
                var authorization = request.Headers["Authorization"];

                if (string.IsNullOrEmpty(authorization)) throw new Exception("Token não encontrado!");

                if (!authorization.Contains(TOKEN_TYPE))
                    throw new Exception(string.Format("Tipo de token está diferente de {0}!", TOKEN_TYPE));

                return authorization.ToString().Replace(TOKEN_TYPE, "").Trim();
            }
            catch (NullReferenceException) { throw new Exception("Não foi encotrado um tipo de autorização!"); }
            catch (Exception ex) { throw ex; }
        }
    }
}