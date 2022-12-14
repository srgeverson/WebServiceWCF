using AppClassLibraryDomain.model;
using AppClassLibraryDomain.model.DTO;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Net;
using System.ServiceModel.Web;

namespace WebServiceWCF.Service
{
    public class AuthorizationWCF
    {
        private static string SECRET = ConfigurationManager.AppSettings["secret"];
        private static string EXPIRED = ConfigurationManager.AppSettings["expired"];
        private static string TOKEN_TYPE = ConfigurationManager.AppSettings["token"];

        public UsuarioLogado gerarToken(Usuario usuario, UsuarioLogin usuarioLogin, int[] permissoesId)
        {
            try
            {
                //if (!BCryptNet.Verify(usuarioLogin.senha, usuario.Senha)) throw new Exception("Senha inválida!");

                //if (string.IsNullOrEmpty(SECRET)) throw new Exception("Não foi encontrado a chave secreta de validação do token.");
                //if (string.IsNullOrEmpty(EXPIRED)) throw new Exception("Não foi definido tempo de validação do token.");
                //if (string.IsNullOrEmpty(TOKEN_TYPE)) throw new Exception("Não foi definido tipo do token.");

                //int[] permissoesId = permissaoService.PermissoesPorEmail(usuarioLogin.login)
                //    .Select(permissao => permissao.Id)
                //    .ToList()
                //    .ConvertAll(x => x.Value)
                //    .ToArray();
                //var utcNow = DateTimeOffset.UtcNow;
                var extraHeaders = new Dictionary<string, object> { };
                //var payload = new PayloadToken()
                //{
                //    sub = usuario.Id,
                //    iss = Assembly.GetExecutingAssembly().GetName().Name,
                //    roles = permissoesId,
                //    name = usuario.Nome,
                //    iat = utcNow.ToUnixTimeSeconds(),
                //    exp = utcNow.AddSeconds(Convert.ToDouble(EXPIRED)).ToUnixTimeSeconds(),
                //    aud = "AppGenérico"
                //};
                //var key = Convert.FromBase64String(SECRET);
                //IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
                //IJsonSerializer serializer = new JsonNetSerializer();
                //IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
                //IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
                //var token = encoder.Encode(extraHeaders, payload, key);

                //return new UsuarioLogado() {
                //    token_type = TOKEN_TYPE,
                //    access_token = token,
                //    expires_in = utcNow.AddSeconds(Convert.ToDouble(EXPIRED)).ToUnixTimeSeconds(),
                //    Mensagem = "Usuário autorizado" };
                return null;
            }
            catch (Exception ex)
            {
                throw new WebFaultException<ResponseDefaultDTO>(new ResponseDefaultDTO() { StatusCode = 401, Mensagem = ex.Message }, HttpStatusCode.Unauthorized);
            }
        }

        public ResponseDefaultDTO validarToken(IncomingWebRequestContext request)
        {
            //try
            //{
            //    string token = ExtrairToken(request);

            //    IJsonSerializer serializer = new JsonNetSerializer();
            //    var provider = new UtcDateTimeProvider();
            //    IJwtValidator validator = new JwtValidator(serializer, provider);
            //    IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            //    IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
            //    IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);
            //    var key = Convert.FromBase64String(SECRET);
            //    return new ResponseDefaultDTO()
            //    {
            //        StatusCode = 200,
            //        Mensagem = string.IsNullOrEmpty(decoder.Decode(token, key, verify: true)) ? string.Empty : "Token válido!"
            //    };
            //}
            //catch (TokenNotYetValidException tnyvex)
            //{
            //    throw new WebFaultException<ResponseDefaultDTO>(new ResponseDefaultDTO() { StatusCode = 401, Mensagem = tnyvex.Message }, HttpStatusCode.Unauthorized);
            //}
            //catch (TokenExpiredException teex)
            //{
            //    throw new WebFaultException<ResponseDefaultDTO>(new ResponseDefaultDTO() { StatusCode = 401, Mensagem = teex.Message }, HttpStatusCode.Unauthorized);
            //}
            //catch (SignatureVerificationException svex)
            //{
            //    throw new WebFaultException<ResponseDefaultDTO>(new ResponseDefaultDTO() { StatusCode = 401, Mensagem = svex.Message }, HttpStatusCode.Unauthorized);
            //}
            //catch (Exception ex)
            //{
            //    throw new WebFaultException<ResponseDefaultDTO>(new ResponseDefaultDTO() { StatusCode = 401, Mensagem = ex.Message }, HttpStatusCode.Unauthorized);
            //}
            return null;
        }

        public PayloadTokenDTO validarAcesso(IncomingWebRequestContext request, int[] roles)
        {
            //try
            //{
            //    string token = ExtrairToken(request);

            //    IJsonSerializer serializer = new JsonNetSerializer();
            //    var provider = new UtcDateTimeProvider();
            //    IJwtValidator validator = new JwtValidator(serializer, provider);
            //    IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            //    IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
            //    IJwtDecoder decoder = new JwtDecoder(serializer, validator, urlEncoder, algorithm);
            //    var key = Convert.FromBase64String(SECRET);
            //    var payloadToken = new JsonNetSerializer().Deserialize<PayloadTokenDTO>(decoder.Decode(token, key, verify: true));

            //    return payloadToken;
            //}
            //catch (TokenNotYetValidException tnyvex)
            //{
            //    throw new WebFaultException<ResponseDefaultDTO>(new ResponseDefaultDTO() { StatusCode = 401, Mensagem = tnyvex.Message }, HttpStatusCode.Unauthorized);
            //}
            //catch (TokenExpiredException teex)
            //{
            //    throw new WebFaultException<ResponseDefaultDTO>(new ResponseDefaultDTO() { StatusCode = 401, Mensagem = teex.Message }, HttpStatusCode.Unauthorized);
            //}
            //catch (SignatureVerificationException svex)
            //{
            //    throw new WebFaultException<ResponseDefaultDTO>(new ResponseDefaultDTO() { StatusCode = 401, Mensagem = svex.Message }, HttpStatusCode.Unauthorized);
            //}
            //catch (Exception ex)
            //{
            //    throw new WebFaultException<ResponseDefaultDTO>(new ResponseDefaultDTO() { StatusCode = 401, Mensagem = ex.Message }, HttpStatusCode.Unauthorized);
            //}
            return null;
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