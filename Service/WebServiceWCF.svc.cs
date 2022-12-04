using AppClassLibraryClient.mapper;
using AppClassLibraryClient.model;
using AppClassLibraryDomain.DAO;
using AppClassLibraryDomain.exception;
using AppClassLibraryDomain.facade;
using AppClassLibraryDomain.service;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using System.ServiceModel.Activation;
using System.ServiceModel.Web;
using WebServiceWCF.Service;

namespace WebServiceWCF
{
    [AspNetCompatibilityRequirements(RequirementsMode = AspNetCompatibilityRequirementsMode.Allowed)]
    public class WebServiceWCF : IWebServiceWCF
    {
        private IAuthorizationServerFacade _authorizationServerFacade;
        private ISistemaService _sistemaService;
        private UsuarioMapper _usuarioMapper;

        public WebServiceWCF()
        {
            //if (string.IsNullOrEmpty(ConexaoDAO.URLCONEXAO))
            //    ConexaoDAO.URLCONEXAO = ConfigurationManager.AppSettings["connectionString"];

            if (_usuarioMapper == null)
                _usuarioMapper = new UsuarioMapper();

            if (_sistemaService == null)
                _sistemaService = new SistemaService();

            _sistemaService.Sistema(FileVersionInfo.GetVersionInfo(Assembly.GetExecutingAssembly().Location).ProductName);

        }

        public UsuarioLogado Autenticar(UsuarioLogin usuarioLogin)
        {
            try
            {
                //ok
                if (String.IsNullOrEmpty(usuarioLogin.login) || String.IsNullOrEmpty(usuarioLogin.senha))
                    throw new WebFaultException<TokenValidado>(new TokenValidado() { StatusCode = 400, Mensagem = "E-mail ou senha não informado!" }, HttpStatusCode.BadRequest);
                //ok
                var usuario = _authorizationServerFacade.BuscarPorEmail(usuarioLogin.login);
                if (usuario == null)
                    throw new AuthorizationServerException("Não foi encontrado usuário vinculado ao e-mail informado!");
                //ok
                var expired = ConfigurationManager.AppSettings["expired"];
                var token_type = ConfigurationManager.AppSettings["token"];
                var secret = ConfigurationManager.AppSettings["secret"];
                _authorizationServerFacade.ValidarConfigucaoDoToken(
                    secret,
                    expired,
                    token_type
                    );
                long[] permissoesId = _authorizationServerFacade.PermissoesPorEmail(usuarioLogin.login);
                var utcNow = DateTimeOffset.UtcNow;
                var payload = new PayloadToken()
                {
                    sub = usuario.Id,
                    iss = Assembly.GetExecutingAssembly().GetName().Name,
                    roles = permissoesId,
                    name = usuario.Nome,
                    iat = utcNow.ToUnixTimeSeconds(),
                    exp = utcNow.AddSeconds(Convert.ToDouble(expired)).ToUnixTimeSeconds(),
                    aud = "AppGenérico"
                };
                var extraHeaders = new Dictionary<string, object> { };
                var key = Convert.FromBase64String(secret);
                IJwtAlgorithm algorithm = new HMACSHA256Algorithm(); // symmetric
                IJsonSerializer serializer = new JsonNetSerializer();
                IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
                IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
                var token = encoder.Encode(extraHeaders, payload, key);


                var usuarioLogado = new UsuarioLogado()
                {
                    token_type = token_type,
                    access_token = token,
                    expires_in = utcNow.AddSeconds(Convert.ToDouble(expired)).ToUnixTimeSeconds(),
                    Mensagem = "Usuário autorizado"
                };
                _authorizationServerFacade.AtualizaDataUltimoAcesso(usuario.Id);

                return usuarioLogado;

            }
            catch (AuthorizationServerException asex)
            {
                throw new WebFaultException<TokenValidado>(new TokenValidado() { StatusCode = 400, Mensagem = asex.Message }, HttpStatusCode.BadRequest);
            }
            catch (Exception ex)
            {
                throw new WebFaultException<TokenValidado>(new TokenValidado() { StatusCode = 500, Mensagem = ex.Message }, HttpStatusCode.BadRequest);
            }
        }

        public TokenValidado Autorizar()
        {
            var authorizationWCF = new AuthorizationWCF();
            return authorizationWCF.validarToken(WebOperationContext.Current.IncomingRequest);
        }

        public UsuarioResponse CadastrarUsuario(UsuarioRequest usuarioRequest)
        {
            try
            {
                if (usuarioRequest == null)
                    throw new AuthorizationServerException("Dados inválidos!");
                var usuario = _usuarioMapper.ToModel(usuarioRequest);
                var usuarioNovo = _authorizationServerFacade.CadastrarUsuario(usuario);
                var usuarioResponse = _usuarioMapper.ToResponse(usuarioNovo);
                return usuarioResponse;
            }
            catch (AuthorizationServerException asex)
            {
                throw new WebFaultException<TokenValidado>(new TokenValidado() { StatusCode = 400, Mensagem = asex.Message }, HttpStatusCode.BadRequest);
            }
            catch (Exception ex)
            {
                throw new WebFaultException<TokenValidado>(new TokenValidado() { StatusCode = 500, Mensagem = ex.Message }, HttpStatusCode.BadRequest);
            }
        }

        public string GerarMensagemDeBoasVindas(string nome)
        {
            return string.Format("Seja bem vindo {0}!", nome);
        }

        public IList<UsuarioResponse> ListarTodosUsuarios() => _usuarioMapper.ToListResponse(_authorizationServerFacade.ListarTodosUsuarios());
        public Pessoa NomeESobreNome(string nome, string sobreNome)
        {
            return new Pessoa() { Nome = nome, SobreNome = sobreNome };
        }
    }
}
