using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Dispatcher;
using System.ServiceModel.Web;

namespace WebServiceWCF
{
    public class ServerMessageLogger : IDispatchMessageInspector
    {
        public object AfterReceiveRequest(ref Message request, IClientChannel channel, InstanceContext instanceContext)
        {
            //string token = null;
            //IncomingWebRequestContext request = WebOperationContext.Current.IncomingRequest;
            //token = request.Headers["Authorization"].ToString().Replace("Bearer", "").Trim();
            return null;
        }

     
        public void BeforeSendReply(ref Message reply, object correlationState)
        {
            WebOperationContext ctx = WebOperationContext.Current;
            ctx.OutgoingResponse.Headers.Add("Access-Control-Allow-Origin", "*");
        }
    }
}