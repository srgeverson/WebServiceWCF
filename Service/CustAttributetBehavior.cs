using System;
using System.Net;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.ServiceModel.Web;
using AppClassLibraryDomain.facade;
using Spring.Context.Support;
using Spring.Context;
using AppClassLibraryDomain.model.DTO;
using System.Configuration;
using System.Reflection;
using AppClassLibraryDomain.exception;

namespace WebServiceWCF
{
    public class CustAttributetBehavior : Attribute, IOperationBehavior, IParameterInspector
    {
        private long[] _roles;
        private IAuthorizationServerFacade _authorizationServerFacade;
        private ConfiguracaoTokenDTO _configuracaoTokenDTO;
        private static readonly IApplicationContext CONTEXT = ContextRegistry.GetContext();

        public CustAttributetBehavior()
        {
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
        }

        public CustAttributetBehavior(params long[] roles)
        {
            _roles = roles;
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
        }

        public void ApplyDispatchBehavior(OperationDescription operationDescription, DispatchOperation dispatchOperation)
        {
            dispatchOperation.ParameterInspectors.Add(this);
        }

        public void AfterCall(string operationName, object[] outputs, object returnValue, object correlationState) { }

        public object BeforeCall(string operationName, object[] inputs)
        {
            try
            {
                var authorization = WebOperationContext.Current.IncomingRequest.Headers["Authorization"];
                var payloadTokenDTO = _authorizationServerFacade.ValidarAcesso(_configuracaoTokenDTO, authorization, _roles);
                _authorizationServerFacade.ValidarRoles(_roles, payloadTokenDTO.roles);
            }
            catch (AuthorizationServerException asex)
            {
                throw new WebFaultException<TokenValidado>(
                                       new TokenValidado()
                                       {
                                           StatusCode = (int)(asex.Status == null ? 403 : asex.Status),
                                           Mensagem = asex.Message
                                       },
                                       (HttpStatusCode)(int)(asex.Status == null ? 403 : asex.Status)
                                       );
            }
            catch (Exception ex)
            {
                throw new WebFaultException<TokenValidado>(
                        new TokenValidado()
                        {
                            StatusCode = 500,
                            Mensagem = ex.Message
                        },
                        HttpStatusCode.InternalServerError
                        );
            }
            return null;
        }

        public void AddBindingParameters(OperationDescription operationDescription, BindingParameterCollection bindingParameters) { }

        public void ApplyClientBehavior(OperationDescription operationDescription, ClientOperation clientOperation) { }

        public void Validate(OperationDescription operationDescription) { }
    }
}