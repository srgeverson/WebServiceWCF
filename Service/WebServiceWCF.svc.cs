using AppClassLibraryClient.mapper;
using AppClassLibraryClient.model;
using AppClassLibraryDomain.exception;
using AppClassLibraryDomain.facade;
using AppClassLibraryDomain.model.DTO;
using AppClassLibraryDomain.service;
using AppClassLibraryDomain.utils;
using Spring.Context;
using Spring.Context.Support;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Net;
using System.Reflection;
using System.ServiceModel.Activation;
using System.ServiceModel.Web;

namespace WebServiceWCF
{
    [AspNetCompatibilityRequirements(RequirementsMode = AspNetCompatibilityRequirementsMode.Allowed)]
    public class WebServiceWCF : IWebServiceWCF
    {
        #region atributos
        private IAuthorizationServerFacade _authorizationServerFacade;
        private ISistemaService _sistemaService;
        private UsuarioMapper _usuarioMapper;
        private ConfiguracaoTokenDTO _configuracaoTokenDTO;
        private static readonly IApplicationContext CONTEXT = ContextRegistry.GetContext();
        #endregion

        public WebServiceWCF()
        {
            try
            {
                if (_usuarioMapper == null)
                    _usuarioMapper = new UsuarioMapper();

                if (_authorizationServerFacade == null)
                    _authorizationServerFacade = (IAuthorizationServerFacade)CONTEXT.GetObject("AuthorizationServerFacade");

                if (_configuracaoTokenDTO == null)
                {
                    _configuracaoTokenDTO = _authorizationServerFacade.ValidarConfigucaoDoToken(
                    ConfigurationManager.AppSettings["secret"],
                    ConfigurationManager.AppSettings["expired"],
                    ConfigurationManager.AppSettings["token"],
                    Assembly.GetExecutingAssembly().GetName().Name
                    );
                }

                if (_sistemaService == null)
                    _sistemaService = (ISistemaService)CONTEXT.GetObject("SistemaService");

                _sistemaService.Sistema(_configuracaoTokenDTO.App);
            }
            catch (SistemaException sex)
            {
                throw new WebFaultException<ResponseDefaultDTO>(new ResponseDefaultDTO() { StatusCode = (int)(sex.Status == null ? 400 : sex.Status), Mensagem = sex.Message }, EnumUtils<HttpStatusCode>.FindEnumByValue(sex.Status));
            }
            catch (Exception ex)
            {
                throw new WebFaultException<ResponseDefaultDTO>(new ResponseDefaultDTO() { StatusCode = 500, Mensagem = ex.Message }, HttpStatusCode.InternalServerError);
            }
        }

        public UsuarioLogadoDTO Autenticar(UsuarioLogin usuarioLogin)
        {
            try
            {
                if (usuarioLogin == null)
                    throw new AuthorizationServerException("Informações de login não fornecidas");
                if (String.IsNullOrEmpty(usuarioLogin.login) || String.IsNullOrEmpty(usuarioLogin.senha))
                    throw new AuthorizationServerException("E-mail ou senha não informado!");

                var usuario = _authorizationServerFacade.BuscarPorEmail(usuarioLogin.login);
                if (usuario == null)
                    throw new AuthorizationServerException("Não foi encontrado usuário vinculado ao e-mail informado!");
                _authorizationServerFacade.ValidarSenha(usuarioLogin.senha, usuario);

                long[] permissoesId = _authorizationServerFacade.PermissoesPorEmailESistema(usuarioLogin.login, _configuracaoTokenDTO.App);

                var usuarioLogadoDTO = _authorizationServerFacade.GerarToken(usuario, _configuracaoTokenDTO, permissoesId);
                _authorizationServerFacade.AtualizaDataUltimoAcesso(usuario.Id);

                return usuarioLogadoDTO;

            }
            catch (AuthorizationServerException asex)
            {
                throw new WebFaultException<ResponseDefaultDTO>(
                    new ResponseDefaultDTO()
                    {
                        StatusCode = (int)(asex.Status == null ? 401 : asex.Status),
                        Mensagem = asex.Message
                    },
                    (HttpStatusCode)(int)(asex.Status == null ? 401 : asex.Status)
                    );
            }
            catch (Exception ex)
            {
                throw new WebFaultException<ResponseDefaultDTO>(new ResponseDefaultDTO() { StatusCode = 500, Mensagem = ex.Message }, HttpStatusCode.BadRequest);
            }
        }

        public ResponseDefaultDTO Autorizar()
        {
            try
            {
                var authorization = WebOperationContext.Current.IncomingRequest.Headers["Authorization"];

                if (string.IsNullOrEmpty(authorization)) throw new Exception("Token não encontrado!");

                if (!authorization.Contains(_configuracaoTokenDTO.Token))
                    throw new Exception(string.Format("Tipo de token está diferente de {0}!", _configuracaoTokenDTO.Token));

                var token = authorization.ToString().Replace(_configuracaoTokenDTO.Token, "").Trim();

                return new ResponseDefaultDTO()
                {
                    StatusCode = 200,
                    Mensagem = _authorizationServerFacade.ValidarToken(_configuracaoTokenDTO, token) ? "Token válido!" : String.Empty
                };
            }
            catch (AuthorizationServerException asex)
            {
                throw new WebFaultException<ResponseDefaultDTO>(
                    new ResponseDefaultDTO()
                    {
                        StatusCode = (int)(asex.Status == null ? 401 : asex.Status),
                        Mensagem = asex.Message
                    },
                    (HttpStatusCode)(asex.Status == null ? 401 : asex.Status)
                    );
            }
            catch (Exception ex)
            {
                throw new WebFaultException<ResponseDefaultDTO>(new ResponseDefaultDTO() { StatusCode = 500, Mensagem = ex.Message }, HttpStatusCode.InternalServerError);
            }
        }

        public UsuarioResponse CadastrarUsuario(UsuarioRequest usuarioRequest)
        {
            try
            {
                if (usuarioRequest == null)
                    throw new NegocioException("Dados inválidos!");
                var usuario = _usuarioMapper.ToModel(usuarioRequest);
                var usuarioNovo = _authorizationServerFacade.CadastrarUsuario(usuario);
                var usuarioResponse = _usuarioMapper.ToResponse(usuarioNovo);
                return usuarioResponse;
            }
            catch (NegocioException nex)
            {
                throw new WebFaultException<ResponseDefaultDTO>(
                    new ResponseDefaultDTO()
                    {
                        StatusCode = (int)(nex.Status == null ? 400 : nex.Status),
                        Mensagem = nex.Message
                    },
                    (HttpStatusCode)(nex.Status == null ? 400 : nex.Status)
                    );
            }
            catch (Exception ex)
            {
                throw new WebFaultException<ResponseDefaultDTO>(
                    new ResponseDefaultDTO()
                    {
                        StatusCode = 500,
                        Mensagem = ex.Message
                    },
                    HttpStatusCode.InternalServerError
                    );
            }
        }

        public string GerarMensagemDeBoasVindas(string nome)
        {
            return string.Format("Seja bem vindo {0}!", nome);
        }

        public IList<UsuarioResponse> ListarTodosUsuarios()
        {
            try
            {
                return _usuarioMapper.ToListResponse(_authorizationServerFacade.ListarTodosUsuarios());
            }
            catch (NegocioException nex)
            {
                throw new WebFaultException<ResponseDefaultDTO>(
                    new ResponseDefaultDTO()
                    {
                        StatusCode = (int)(nex.Status == null ? 400 : nex.Status),
                        Mensagem = nex.Message
                    },
                    (HttpStatusCode)(nex.Status == null ? 400 : nex.Status)
                    );
            }
            catch (Exception ex)
            {
                throw new WebFaultException<ResponseDefaultDTO>(
                    new ResponseDefaultDTO()
                    {
                        StatusCode = 500,
                        Mensagem = ex.Message
                    },
                    HttpStatusCode.InternalServerError
                    );
            }
        }

        public Pessoa NomeESobreNome(string nome, string sobreNome)
        {
            try
            {
                return new Pessoa() { Nome = nome, SobreNome = sobreNome };
            }
            catch (NegocioException nex)
            {
                throw new WebFaultException<ResponseDefaultDTO>(
                    new ResponseDefaultDTO()
                    {
                        StatusCode = (int)(nex.Status == null ? 400 : nex.Status),
                        Mensagem = nex.Message
                    },
                    (HttpStatusCode)(nex.Status == null ? 400 : nex.Status)
                    );
            }
            catch (Exception ex)
            {
                throw new WebFaultException<ResponseDefaultDTO>(
                    new ResponseDefaultDTO() 
                    { 
                        StatusCode = 500, 
                        Mensagem = ex.Message 
                    }, 
                    HttpStatusCode.InternalServerError
                    );
            }
        }
    }
}
