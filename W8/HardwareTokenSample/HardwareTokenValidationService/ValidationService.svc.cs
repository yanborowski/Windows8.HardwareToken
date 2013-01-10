using HardwareTokenSample;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Text;

namespace HardwareTokenValidationService
{
    // NOTE: You can use the "Rename" command on the "Refactor" menu to change the class name "Service1" in code, svc and config file together.
    // NOTE: In order to launch WCF Test Client for testing this service, please select Service1.svc or Service1.svc.cs at the Solution Explorer and start debugging.
    public class ValidationService : IValidationService
    {
        
        public bool ValidateToken(byte[] token, byte[] nonce, byte[] certificate, byte[] signature)
        {
            return CloudVerification.ValidateData(nonce, token, signature, certificate);
        }
    }
}
