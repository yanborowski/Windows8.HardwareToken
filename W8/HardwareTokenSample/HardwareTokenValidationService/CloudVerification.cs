using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace HardwareTokenSample
{
    public static class CloudVerification
    {

        #region publickey
        static readonly byte[] gRootPublicKey = new byte[] {
            0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02, 0x01, 0x00, 0xa8, 0xef, 0xce, 0xef, 0xec, 0x12, 0x8b,
            0x92, 0x94, 0xed, 0xcf, 0xaa, 0xa5, 0x81, 0x8d, 0x4f, 0xa4, 0xad, 0x4a, 0xec, 0xa5, 0xf0, 0xda,
            0xa8, 0x3d, 0xb6, 0xe5, 0x61, 0x01, 0x99, 0xce, 0x3a, 0x23, 0x73, 0x5a, 0x58, 0x67, 0x9f, 0xf5,
            0xb6, 0x5b, 0xf5, 0x4f, 0xf9, 0xa0, 0x9b, 0x75, 0x1e, 0xcc, 0x53, 0x62, 0x10, 0x3c, 0xa7, 0xa5,
            0x3a, 0x3b, 0xe6, 0x24, 0x22, 0xf4, 0x18, 0x96, 0x2e, 0xf2, 0xfc, 0xd9, 0xa5, 0x88, 0xc6, 0xfd,
            0x51, 0xf0, 0x31, 0xc3, 0xbd, 0x01, 0xdc, 0x45, 0xb6, 0xf6, 0x40, 0x2b, 0xb7, 0x45, 0x7b, 0x45,
            0x4f, 0xed, 0xc0, 0xb4, 0x7c, 0x58, 0x44, 0xf9, 0x89, 0xfb, 0x6a, 0x75, 0x3b, 0x6d, 0xf1, 0x2e,
            0xac, 0x35, 0xa1, 0x5f, 0x7a, 0x94, 0xcd, 0x3a, 0x6d, 0x98, 0xb8, 0xb8, 0x29, 0xe6, 0x33, 0x98,
            0x2e, 0x33, 0x83, 0x7a, 0x86, 0xb7, 0xa8, 0x0a, 0x10, 0xf2, 0x07, 0x32, 0x63, 0xe4, 0x32, 0xed,
            0x4d, 0xab, 0x05, 0x0c, 0xa1, 0xd7, 0x72, 0x49, 0xac, 0x35, 0x2c, 0x2e, 0x70, 0xed, 0xee, 0x12,
            0xfc, 0x23, 0xb1, 0xdc, 0x5a, 0xdf, 0x61, 0xe9, 0x2c, 0x44, 0xcd, 0xae, 0xdb, 0x06, 0x54, 0x8f,
            0x4f, 0xc1, 0xd6, 0x15, 0x72, 0xae, 0x50, 0x89, 0x39, 0x89, 0xf5, 0x95, 0x82, 0xdc, 0xff, 0x41,
            0xeb, 0x89, 0x6f, 0xbc, 0xe0, 0x9f, 0x79, 0x5d, 0x24, 0x16, 0xf7, 0x1d, 0x38, 0xaa, 0xde, 0xd8,
            0x24, 0x97, 0xf6, 0x97, 0x47, 0x74, 0x5b, 0x23, 0x38, 0xc8, 0x9d, 0x2e, 0xaa, 0xd1, 0x1f, 0xce,
            0x09, 0x5c, 0xf1, 0xb9, 0x9f, 0x92, 0x38, 0xd2, 0x11, 0x68, 0x3e, 0xcc, 0x5d, 0x4e, 0xcf, 0x94,
            0x9f, 0xd2, 0x42, 0xbd, 0xe2, 0xf1, 0x4b, 0xf1, 0xa7, 0xa9, 0x5c, 0x79, 0x05, 0xfb, 0x25, 0xf7,
            0xc1, 0x53, 0xf7, 0xd9, 0xc4, 0x4d, 0x79, 0x0f, 0x8a, 0x4d, 0xb4, 0x30, 0x71, 0xa6, 0xe9, 0x51,
            0xe5, 0x8e, 0xe0, 0xc8, 0x83, 0xc7, 0x31, 0xfc, 0x98, 0x46, 0xf6, 0xa2, 0x76, 0xfc, 0xa6, 0x81,
            0x6d, 0x76, 0x90, 0x8d, 0x32, 0x21, 0x1f, 0x2d, 0x3e, 0x69, 0x2b, 0x4f, 0xaa, 0xec, 0x7b, 0xd3,
            0xb9, 0x64, 0xc1, 0xd6, 0xbb, 0x5f, 0xfa, 0x38, 0xc4, 0x41, 0xa6, 0x6d, 0x5a, 0xc3, 0x11, 0x87,
            0xfb, 0xbc, 0x33, 0x70, 0x4a, 0x26, 0x8b, 0xe6, 0x44, 0xdd, 0xcb, 0xb8, 0x30, 0xd3, 0x9b, 0x7b,
            0x1a, 0x0e, 0x03, 0xb4, 0x51, 0xe0, 0xca, 0xbf, 0x7b, 0x3c, 0x57, 0x9a, 0xa0, 0xd8, 0x4b, 0xfe,
            0x7e, 0x36, 0xd8, 0x81, 0xfa, 0x25, 0xbd, 0x7e, 0x03, 0xf5, 0x59, 0x2c, 0xf6, 0xd7, 0xa7, 0x6d,
            0xdd, 0x10, 0x77, 0x77, 0x09, 0xae, 0x76, 0xe2, 0x85, 0x33, 0xa6, 0x7d, 0x71, 0x20, 0xf8, 0x3a,
            0x4f, 0x2a, 0xb6, 0xea, 0x42, 0x29, 0xd0, 0xd3, 0xc6, 0x29, 0x4b, 0x05, 0x2c, 0xe7, 0xb8, 0x4a,
            0xcf, 0xd2, 0xbb, 0x82, 0x20, 0x30, 0x9b, 0xa2, 0x4d, 0x1f, 0x78, 0x2c, 0xd9, 0x54, 0x13, 0xd8,
            0x2a, 0x28, 0x68, 0x51, 0x56, 0xa5, 0xf7, 0xdb, 0xae, 0x59, 0x0e, 0xb9, 0xd1, 0x30, 0x97, 0x82,
            0x04, 0x66, 0xa5, 0x02, 0x3c, 0x25, 0xfa, 0xdd, 0xed, 0x09, 0xc2, 0x60, 0xbc, 0x17, 0x6c, 0xa1,
            0x5a, 0xb6, 0x97, 0xcc, 0x8a, 0x13, 0x56, 0xf6, 0xb4, 0xae, 0xdf, 0xcf, 0x7e, 0x40, 0x2f, 0x49,
            0x41, 0xe0, 0x63, 0x8e, 0x58, 0x20, 0xcc, 0xa3, 0x4f, 0x33, 0x3b, 0x9b, 0xcf, 0x3c, 0x72, 0x7e,
            0x48, 0x41, 0x42, 0x3d, 0x63, 0xe3, 0x5e, 0xe7, 0x75, 0x6c, 0x7f, 0xef, 0x6d, 0x80, 0x09, 0xa4,
            0x2b, 0xa4, 0x3e, 0xde, 0xe4, 0x2b, 0x2c, 0x2b, 0xa9, 0x44, 0x56, 0x83, 0xbe, 0xb6, 0x6e, 0x60,
            0xb9, 0x16, 0x1a, 0xe1, 0x62, 0xe9, 0x54, 0x9d, 0xbf, 0x02, 0x03, 0x01, 0x00, 0x01};
        #endregion

        /// <summary>
        /// Enumeration type that defines the different hardware types in a device.
        /// </summary>
        enum HardwareIdType
        {
            Invalid = 0,
            Processor = 1,
            Memory = 2,
            DiskDevice = 3,
            NetworkAdapter = 4,
            DockingStation = 6,
            MobileBroadband = 7,
            Bluetooth = 8,
            SmBios = 9
        };

        /// <summary>
        /// Defines Id for an individual hardware in the device. type is one of the enumeration values
        /// of HardwareIdType. value is the corresponding id value for the hardware.
        /// </summary>
        struct HardwareId
        {
            public UInt16 type;
            public UInt16 value;
        };

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_PSS_PADDING_INFO
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pszAlgId;
            internal int cbSalt;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_RSAKEY_BLOB
        {
            internal int Magic;
            internal int BitLength;
            internal int cbPublicExp;
            internal int cbModulos;
            internal int cbPrime1;
            internal int cbPrime2;
        }

        internal static class UnsafeNativeMethods
        {
            [DllImport("ncrypt.dll")]
            internal static extern int NCryptVerifySignature(
                SafeNCryptKeyHandle hKey,
                [In] ref BCRYPT_PSS_PADDING_INFO pPaddingInfo,
                [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbHashValue,
                int cbHashValue,
                [In, MarshalAs(UnmanagedType.LPArray)] byte[] pbSignature,
                int cbSignature,
                uint dwFlags);
        }

        /// <summary>
        /// This function validates that the hardwareId is genuine by using nonce, 
        /// signature and certificate. 
        /// </summary>
        /// <param name="nonce">The nonce that was sent to the client.</param>
        /// <param name="id">Hardware id of the client device that was sent from the client metro app.</param>
        /// <param name="signature">Signature for the nonce and hardwareId sent by the client metro app.</param>
        /// <param name="certificate">Full certificate chain that was sent by the client metro app that was used to 
        ///      sign signature data. This certificate chain is used to verify that the hardware id 
        ///      data is generated by Windows OS on the client system.</param>
        [PermissionSetAttribute(SecurityAction.Demand, Unrestricted = true)]
        public static bool ValidateData(byte[] nonce, byte[] id, byte[] signature, byte[] certificate)
        {
            // Convert the Certificate Chain which is in a serialized format to SignedCms object.
            SignedCms cms = new SignedCms();
            cms.Decode(certificate);

            // Looping through all certificates to find the leaf certificate. 
            X509Certificate2 leafCertificate = null;
            foreach (X509Certificate2 x509 in cms.Certificates)
            {
                bool basicConstraintExtensionExists = false;

                foreach (X509Extension extension in x509.Extensions)
                {
                    if (extension.Oid.FriendlyName == "Basic Constraints")
                    {
                        basicConstraintExtensionExists = true;
                        X509BasicConstraintsExtension ext = (X509BasicConstraintsExtension)extension;
                        if (!ext.CertificateAuthority)
                        {
                            leafCertificate = x509;
                            break;
                        }
                    }
                }

                if (leafCertificate != null)
                {
                    break;
                }

                if (!basicConstraintExtensionExists)
                {
                    if (x509.Issuer != x509.Subject)
                    {
                        leafCertificate = x509;
                        break;
                    }
                }
            }

            if (leafCertificate == null)
            {
                throw new ArgumentException("Leaf certificate could not be found");
            }

            // Validating the certificate chain. Ignore the errors due to online revocation check not 
            // being available. Also we are not failing validation due to expired certificates. Microsoft
            // will be revoking the certificates that were exploided. 
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid |
                X509VerificationFlags.IgnoreCtlNotTimeValid |
                X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown |
                X509VerificationFlags.IgnoreEndRevocationUnknown |
                X509VerificationFlags.IgnoreCtlSignerRevocationUnknown;

            chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.4.1.311.10.5.40"));

            bool result = chain.Build(leafCertificate);
            /*if (!result)
            {
                foreach (X509ChainStatus status in chain.ChainStatus)
                {
                    switch (status.Status)
                    {
                        case X509ChainStatusFlags.NoError:
                        case X509ChainStatusFlags.NotTimeValid:
                        case X509ChainStatusFlags.NotTimeNested:
                        case X509ChainStatusFlags.CtlNotTimeValid:
                        case X509ChainStatusFlags.RevocationStatusUnknown:
                        case X509ChainStatusFlags.OfflineRevocation:
                            break;

                        default:
                            throw new ArgumentException("Chain verification failed with status " + status.Status);
                    }
                }
            }*/

            // gRootPublicKey is the hard coded public key for the root certificate. 
            // Compare the public key on the root certificate with the hard coded one. 
            // They must match.
            X509Certificate2 rootCertificate = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
            if (!rootCertificate.PublicKey.EncodedKeyValue.RawData.SequenceEqual(gRootPublicKey))
            {
                throw new ArgumentException("Public key of the root certificate is not as expected.");
            }

            // Signature contains both nonce and hardwareId. So creating the combined data;
            byte[] blob;
            if (nonce == null)
            {
                blob = id;
            }
            else
            {
                blob = nonce.Concat(id).ToArray();
            }

            // Using the leaf Certificate we verify the signature of blob. The RSACryptoServiceProvider does not
            // provide a way to pass in different padding mode. So we use Win32 NCryptVerifySignature API instead.
            RSACryptoServiceProvider rsaCsp = leafCertificate.PublicKey.Key as RSACryptoServiceProvider;
            RSAParameters parameters = rsaCsp.ExportParameters(false);
            SHA1Managed sha1 = new SHA1Managed();
            byte[] blobHash = sha1.ComputeHash(blob);

            CngKey cngKey = CngKey.Import(GetPublicKey(parameters), CngKeyBlobFormat.GenericPublicBlob);
            BCRYPT_PSS_PADDING_INFO paddingInfo = new BCRYPT_PSS_PADDING_INFO
            {
                pszAlgId = CngAlgorithm.Sha1.Algorithm,
                cbSalt = 0
            };

            int result2 = UnsafeNativeMethods.NCryptVerifySignature(
                cngKey.Handle,
                ref paddingInfo,
                blobHash,
                blobHash.Length,
                signature,
                signature.Length,
                8); // NCRYPT_PAD_PSS_FLAG

            if (result2 != 0) // 0 means ERROR_SUCCESS
            {
                return false; //throw new ArgumentException("Verification failed with " + result2);
            }

            return true;
        }

        /// <summary>
        /// In this method you should implement your business logic based on hardware ID.
        /// You should call this method after ValidateData to make sure id is trustable.
        /// </summary>
        /// <param name="id">Hardware id of the client device that was sent from the client metro app.</param>
        public static void ProcessData(byte[] id)
        {
            // Convert serialized hardwareId to well formed HardwareId structures so that 
            // it can be easily consumed. 
            if (id.Length % 4 != 0)
            {
                throw new ArgumentException("Invalid hardware id");
            }

            HardwareId[] hardwareIds = new HardwareId[id.Length / 4];
            for (int index = 0; index < hardwareIds.Length; index++)
            {
                hardwareIds[index].type = BitConverter.ToUInt16(id, index * 4);
                hardwareIds[index].value = BitConverter.ToUInt16(id, index * 4 + 2);

                switch ((HardwareIdType)hardwareIds[index].type)
                {
                    case HardwareIdType.Processor:
                        // implement your business logic based on hardwareIds[index].value 
                        break;

                    case HardwareIdType.Memory:
                        // implement your business logic based on hardwareIds[index].value 
                        break;

                    case HardwareIdType.NetworkAdapter:
                        // implement your business logic based on hardwareIds[index].value 
                        break;

                    // Add other case statements for the other Hardware types here.
                }
            }
        }

        [System.Security.SecuritySafeCritical]
        private static byte[] GetPublicKey(RSAParameters parameters)
        {
            int blobSize = Marshal.SizeOf(typeof(BCRYPT_RSAKEY_BLOB)) +
                parameters.Exponent.Length +
                parameters.Modulus.Length;

            byte[] rsaBlob = new byte[blobSize];

            unsafe
            {
                fixed (byte* pRsaBlob = rsaBlob)
                {
                    BCRYPT_RSAKEY_BLOB* pBcryptBlob;
                    pBcryptBlob = (BCRYPT_RSAKEY_BLOB*)pRsaBlob;
                    pBcryptBlob->Magic = 0x31415352; // RsaPublic 
                    pBcryptBlob->BitLength = parameters.Modulus.Length * 8;
                    pBcryptBlob->cbPublicExp = parameters.Exponent.Length;
                    pBcryptBlob->cbModulos = parameters.Modulus.Length;

                    int offset = Marshal.SizeOf(typeof(BCRYPT_RSAKEY_BLOB));
                    System.Buffer.BlockCopy(parameters.Exponent, 0, rsaBlob, offset, parameters.Exponent.Length);
                    offset += parameters.Exponent.Length;
                    System.Buffer.BlockCopy(parameters.Modulus, 0, rsaBlob, offset, parameters.Modulus.Length);
                }
            }

            return rsaBlob;
        }
    }
}