using AppClassLibraryClient.model;
using System.Collections.Generic;
using System.ServiceModel;
using System.ServiceModel.Web;

namespace WebServiceWCF
{
    [ServiceContract]
    [CustContractBehavior]
    public interface IWebServiceWCF
    {

        [OperationContract]
        [WebInvoke(Method = "GET", ResponseFormat = WebMessageFormat.Json, UriTemplate = "boas-vindas?nome={nome}")]
        string GerarMensagemDeBoasVindas(string nome);

        [OperationContract]
        [WebInvoke(Method = "GET", ResponseFormat = WebMessageFormat.Json, UriTemplate = "nome-sobre-nome?nome={nome}&sobreNome={sobreNome}")]
        Pessoa NomeESobreNome(string nome, string sobreNome);

        [OperationContract]
        [WebInvoke(Method = "POST", RequestFormat = WebMessageFormat.Json, ResponseFormat = WebMessageFormat.Json, BodyStyle = WebMessageBodyStyle.Bare, UriTemplate = "login")]
        UsuarioLogado Autenticar(UsuarioLogin usuarioLogin);

        [OperationContract]
        [WebInvoke(Method = "POST", RequestFormat = WebMessageFormat.Json, ResponseFormat = WebMessageFormat.Json, BodyStyle = WebMessageBodyStyle.Bare, UriTemplate = "validar")]
        TokenValidado Autorizar();

        [OperationContract]
        [WebInvoke(Method = "GET", ResponseFormat = WebMessageFormat.Json, UriTemplate = "usuarios/listar")]
        [CustAttributetBehavior]
        List<UsuarioResponse> ListarTodosUsuarios();

        [OperationContract]
        [WebInvoke(Method = "POST", ResponseFormat = WebMessageFormat.Json, UriTemplate = "usuarios/cadastrar")]
        [CustAttributetBehavior(4)]
        UsuarioResponse CadastrarUsuario(UsuarioRequest usuarioRequest);
    }
}
