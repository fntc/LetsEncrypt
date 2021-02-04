using LetsEncrypt.Client;
using LetsEncrypt.Client.Entities;
using NUnit.Framework;
using System;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace LetsEncrypt.Test
{
    public class FullProcessMT : BaseUT

    {
        [Test]
        public async Task Run()
        {
            // Create client alias core object + specify which environment you want to use
            var acmeClient = new AcmeClient(EnviromentUri);

            // Create new Account
            var account = await acmeClient.CreateNewAccountAsync(ContactEmail);

            // Create new Order
            var order = await acmeClient.NewOrderAsync(account, Identifiers);

            // Create DNS challenge (DNS is required for wildcard certificate)
            var challenges = await acmeClient.GetDnsChallenges(account, order);

            try
            {
                // Creation of all DNS entries
                foreach (var challenge in challenges)
                {
                    var dnsKey = challenge.VerificationKey;
                    var dnsText = challenge.VerificationValue;


                    await AddTxtEntry(challenge.DnsKey, dnsText);

                    // value can be e.g.: eBAdFvukOz4Qq8nIVFPmNrMKPNlO8D1cr9bl8VFFsJM

                    // Create DNS TXT record e.g.:
                    // key: _acme-challenge.your.domain.com
                    // value: eBAdFvukOz4Qq8nIVFPmNrMKPNlO8D1cr9bl8VFFsJM
                }

                await Task.Delay(60000);

                // Validation of all DNS entries
                foreach (var challenge in challenges)
                {
                    await acmeClient.ValidateChallengeAsync(account, challenge);
                    Challenge freshChallenge;
                    do
                    {
                        // Verify status of challenge
                        freshChallenge = await acmeClient.GetChallengeAsync(account, challenge);
                        if (freshChallenge.Status == ChallengeStatus.Invalid)
                        {
                            throw new Exception("Something is wrong with your DNS TXT record(s)!");
                        }

                        if (freshChallenge.Status != ChallengeStatus.Valid)
                            await Task.Delay(5000);

                    } while (freshChallenge.Status == ChallengeStatus.Valid);
                }

            }
            finally
            {
                foreach (var challenge in challenges)
                {
                    await ClearTxtEntries(challenge.DnsKey);
                }
            }

            var commonName = Identifiers.FirstOrDefault(i => !i.StartsWith("*"));

            // Generate certificate
            var certificate = await acmeClient.GenerateCertificateAsync(account, order, commonName);

            // Save files locally
            var password = "mysupersecretpassword11!";
            await LocalFileHandler.WriteAsync($"{commonName}.pfx", certificate.GeneratePfx(password));
            await LocalFileHandler.WriteAsync($"{commonName}.crt", certificate.GenerateCrt(password));
            await LocalFileHandler.WriteAsync($"{commonName}.crt.pem", certificate.GenerateCrtPem(password));
            await LocalFileHandler.WriteAsync($"{commonName}.key.pem", certificate.GenerateKeyPem());

            Assert.Pass();
        }

        protected virtual async Task ClearTxtEntries(string name)
        {
            var match = Regex.Match(name, "(.*)\\.([a-z0-9\\-]+\\.[a-z]+)$");
            var domain = match.Groups[2].Value;
            var txtName = match.Groups[1].Value;

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Auth-API-Token", DnsApiKey);

                var zoneResponse = await client.GetAsync($"https://dns.hetzner.com/api/v1/zones?name={domain}");
                var zone = JsonConvert.DeserializeObject<JObject>(await zoneResponse.Content.ReadAsStringAsync());
                var zoneId = ((zone["zones"] as JArray)[0] as JObject)["id"].ToString();
                var recordsResponse = await client.GetAsync($"https://dns.hetzner.com/api/v1/records?zone_id={zoneId}");
                var jrecords =
                    JsonConvert.DeserializeObject<JObject>(await recordsResponse.Content.ReadAsStringAsync());
                var records = (jrecords["records"] as JArray).Where(r =>
                    (r as JObject)["name"].ToString().Equals(txtName, StringComparison.InvariantCultureIgnoreCase));

                foreach (var record in records)
                {
                    //delete record			
                    var recordId = record["id"].ToString();
                    var deleteResponse = await client.DeleteAsync($"https://dns.hetzner.com/api/v1/records/{recordId}");
                    deleteResponse.EnsureSuccessStatusCode();
                }
            }
        }

        protected virtual async Task AddTxtEntry(string name, string value)
        {
            var match = Regex.Match(name, "(.*)\\.([a-z0-9\\-]+\\.[a-z]+)$");
            var domain = match.Groups[2].Value;
            var txtName = match.Groups[1].Value;

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Auth-API-Token", DnsApiKey);

                var zoneResponse = await client.GetAsync($"https://dns.hetzner.com/api/v1/zones?name={domain}");
                var zone = JsonConvert.DeserializeObject<JObject>(await zoneResponse.Content.ReadAsStringAsync());
                var zoneId = ((zone["zones"] as JArray)[0] as JObject)["id"].ToString();

                var data = new
                {
                    name = txtName,
                    type = "TXT",
                    value = value,
                    zone_id = zoneId,
                    ttl = 0
                };
                var createResponse = await client.PostAsync($"https://dns.hetzner.com/api/v1/records", new StringContent(JsonConvert.SerializeObject(data), Encoding.UTF8, "application/json"));
                createResponse.EnsureSuccessStatusCode();

            }
        }
    }
}