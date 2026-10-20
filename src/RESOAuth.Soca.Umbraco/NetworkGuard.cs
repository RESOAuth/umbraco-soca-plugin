using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace RESOAuth.Soca.Umbraco;

public static class NetworkGuard
{
    public static Uri ValidateUrl(string value)
    {
        if (value.Length > 8192 || !value.All(char.IsAscii) || Regex.IsMatch(value, @"[\x00-\x20\x7f\\]") || !Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0 || !uri.Host.Contains('.') || IPAddress.TryParse(uri.Host, out _) || value.Split('/').Any(x => Uri.UnescapeDataString(x) is "." or ".."))
            throw new InvalidOperationException("Public HTTPS URL required");
        return uri;
    }

    public static bool PublicAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) || address.IsIPv4MappedToIPv6 || address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.Any)) return false;
        var b = address.GetAddressBytes();
        if (b.Length == 4)
            return b[0] != 0 && b[0] != 10 && b[0] != 127 && b[0] < 224 && !(b[0] == 169 && b[1] == 254) && !(b[0] == 172 && b[1] is >= 16 and <= 31) && !(b[0] == 192 && b[1] == 168) && !(b[0] == 100 && b[1] is >= 64 and <= 127) && !(b[0] == 192 && b[1] == 0) && !(b[0] == 192 && b[1] == 88 && b[2] == 99) && !(b[0] == 198 && b[1] is 18 or 19) && !(b[0] == 198 && b[1] == 51 && b[2] == 100) && !(b[0] == 203 && b[1] == 0 && b[2] == 113);
        // Global unicast only, excluding documentation, Teredo and 6to4.
        return (b[0] & 0xe0) == 0x20 && !(b[0] == 0x20 && b[1] == 0x01 && b[2] < 2) && !(b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) && !(b[0] == 0x3f && b[1] == 0xff && (b[2] & 0xf0) == 0) && !(b[0] == 0x20 && b[1] == 0x02) && !(b[0] == 0x20 && b[1] == 0x01 && b[2] == 0 && b[3] == 0);
    }

    public static HttpClient Client()
    {
        var sockets = new SocketsHttpHandler
        {
            AllowAutoRedirect = false, UseProxy = false, AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(3), PooledConnectionLifetime = TimeSpan.FromSeconds(60),
            ConnectCallback = async (context, ct) =>
            {
                var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, ct);
                if (addresses.Length == 0 || addresses.Any(x => !PublicAddress(x))) throw new HttpRequestException("Non-public or mixed DNS answers rejected");
                var socket = new Socket(addresses[0].AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                try { await socket.ConnectAsync(new IPEndPoint(addresses[0], context.DnsEndPoint.Port), ct); return new NetworkStream(socket, ownsSocket: true); }
                catch { socket.Dispose(); throw; }
            }
        };
        return new HttpClient(new BoundedHandler { InnerHandler = sockets }) { Timeout = TimeSpan.FromSeconds(15), MaxResponseContentBufferSize = 262144 };
    }

    private sealed class BoundedHandler : DelegatingHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            ValidateUrl(request.RequestUri!.AbsoluteUri);
            request.Headers.AcceptEncoding.Clear();
            var response = await base.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode || response.Headers.Location is not null || response.Content.Headers.ContentEncoding.Count > 0 || response.Content.Headers.ContentLength > 262144)
            { response.Dispose(); throw new HttpRequestException("SOCA backchannel response rejected"); }
            try { await response.Content.LoadIntoBufferAsync(262144, cancellationToken); }
            catch { response.Dispose(); throw; }
            return response;
        }
    }

    public static async Task<JsonDocument> Json(HttpClient client, string url, CancellationToken ct)
    {
        using var response = await client.GetAsync(ValidateUrl(url), ct);
        if (response.Content.Headers.ContentType?.MediaType is not ("application/json" or "application/jwk-set+json")) throw new InvalidOperationException("JSON document required");
        var document = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(ct));
        RejectDuplicates(document.RootElement);
        return document;
    }

    public static void RejectDuplicates(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            { if (!names.Add(property.Name)) throw new InvalidOperationException("Duplicate JSON member"); RejectDuplicates(property.Value); }
        }
        else if (element.ValueKind == JsonValueKind.Array) foreach (var child in element.EnumerateArray()) RejectDuplicates(child);
    }
}
