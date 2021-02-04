using LetsEncrypt.Client.Entities;
using System;
using System.Collections.Generic;

namespace LetsEncrypt.Test
{
    public class BaseUT : Startup
    {
        protected string ContactEmail = "my@mail.com";
        protected Uri EnviromentUri = ApiEnvironment.LetsEncryptV2Staging;
        protected List<string> Identifiers = new List<string> { "host.example.com", "*.host.example.com" };
        protected string DnsApiKey = "0000000";
    }
}