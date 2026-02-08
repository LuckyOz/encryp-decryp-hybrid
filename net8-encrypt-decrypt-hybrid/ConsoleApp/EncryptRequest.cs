public class EncryptRequest
{
    public string Data { get; set; } = string.Empty;
    public string? Aes { get; set; }
    public string Iv { get; set; } = string.Empty;
}
