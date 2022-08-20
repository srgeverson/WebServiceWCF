using System;
using System.Linq;
using System.Net;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.ServiceModel.Web;
using System.Threading;
using WebServiceWCF.Service;

namespace WebServiceWCF
{
    public class CustAttributetBehavior : Attribute, IOperationBehavior, IParameterInspector
    {
        public int[] Roles { get; set; }
        private static AuthorizationWCF authorizationWCF;

        public CustAttributetBehavior()
        {
            if (authorizationWCF == null)
                authorizationWCF = new AuthorizationWCF();
        }

        public CustAttributetBehavior(params int[] roles)
        {
            Roles = roles;
            if (authorizationWCF == null)
                authorizationWCF = new AuthorizationWCF();
        }

        public void ApplyDispatchBehavior(OperationDescription operationDescription, DispatchOperation dispatchOperation)
        {
            dispatchOperation.ParameterInspectors.Add(this);
        }

        public void AfterCall(string operationName, object[] outputs, object returnValue, object correlationState)
        {
        }

        public object BeforeCall(string operationName, object[] inputs)
        {
            var payloadToken = authorizationWCF.validarAcesso(WebOperationContext.Current.IncomingRequest, Roles);
            var temPermissao = false;
            foreach (var role in Roles)
            {
                if (payloadToken.roles.ToList().IndexOf(role) > -1)
                {
                    temPermissao = true;
                    break;
                }
            }

            if (temPermissao)
                return null;
            else
                throw new WebFaultException<TokenValidado>(
                        new TokenValidado()
                        {
                            StatusCode = 403,
                            Mensagem = string.Format("Acesso negado. Este usuário não tem a(s) permissão(ões): {0}.", String.Join(",", Roles))
                        },
                        HttpStatusCode.Forbidden
                        );
        }

        public void AddBindingParameters(OperationDescription operationDescription, BindingParameterCollection bindingParameters)
        {
        }

        public void ApplyClientBehavior
        (OperationDescription operationDescription, ClientOperation clientOperation)
        {
        }

        public void Validate(OperationDescription operationDescription)
        {
        }
    }
}