package ghidrassist;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Client for communicating with MCP (Model Context Protocol) server
 * Provides AI-powered analysis capabilities via LLM integration
 */
public class MCPClient {
    private final String mcpEndpoint;
    private final HttpClient httpClient;
    private final int timeoutSeconds;

    public MCPClient(String endpoint) {
        this(endpoint, 30);
    }

    public MCPClient(String endpoint, int timeoutSeconds) {
        this.mcpEndpoint = endpoint;
        this.timeoutSeconds = timeoutSeconds;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(timeoutSeconds))
            .build();
    }

    /**
     * Request AI explanation of a function
     *
     * @param functionCode Decompiled function code
     * @param functionName Name of the function
     * @return AI-generated explanation
     * @throws Exception if request fails
     */
    public String explainFunction(String functionCode, String functionName) throws Exception {
        JSONObject request = new JSONObject();
        request.put("action", "explain_function");
        request.put("function_name", functionName);
        request.put("function_code", functionCode);
        request.put("model", "codellama"); // Default model

        HttpRequest httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(mcpEndpoint + "/analyze"))
            .header("Content-Type", "application/json")
            .timeout(Duration.ofSeconds(timeoutSeconds))
            .POST(HttpRequest.BodyPublishers.ofString(request.toString()))
            .build();

        HttpResponse<String> response = httpClient.send(
            httpRequest,
            HttpResponse.BodyHandlers.ofString()
        );

        if (response.statusCode() != 200) {
            throw new Exception("MCP server returned status " + response.statusCode());
        }

        JSONObject jsonResponse = new JSONObject(response.body());
        return jsonResponse.getString("explanation");
    }

    /**
     * Request AI suggestions for variable names
     *
     * @param currentNames Current variable names
     * @param context Function context (decompiled code)
     * @return Array of suggested names
     * @throws Exception if request fails
     */
    public String[] suggestVariableNames(String[] currentNames, String context) throws Exception {
        JSONObject request = new JSONObject();
        request.put("action", "rename_variables");
        request.put("variables", new JSONArray(currentNames));
        request.put("context", context);

        HttpRequest httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(mcpEndpoint + "/analyze"))
            .header("Content-Type", "application/json")
            .timeout(Duration.ofSeconds(timeoutSeconds))
            .POST(HttpRequest.BodyPublishers.ofString(request.toString()))
            .build();

        HttpResponse<String> response = httpClient.send(
            httpRequest,
            HttpResponse.BodyHandlers.ofString()
        );

        if (response.statusCode() != 200) {
            throw new Exception("MCP server returned status " + response.statusCode());
        }

        JSONObject jsonResponse = new JSONObject(response.body());
        JSONArray suggestions = jsonResponse.getJSONArray("suggestions");

        String[] result = new String[suggestions.length()];
        for (int i = 0; i < suggestions.length(); i++) {
            result[i] = suggestions.getString(i);
        }
        return result;
    }

    /**
     * Detect vulnerabilities in function code
     *
     * @param functionCode Decompiled function code
     * @return JSON array of detected vulnerabilities
     * @throws Exception if request fails
     */
    public JSONArray detectVulnerabilities(String functionCode) throws Exception {
        JSONObject request = new JSONObject();
        request.put("action", "detect_vulnerabilities");
        request.put("function_code", functionCode);

        HttpRequest httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(mcpEndpoint + "/analyze"))
            .header("Content-Type", "application/json")
            .timeout(Duration.ofSeconds(timeoutSeconds))
            .POST(HttpRequest.BodyPublishers.ofString(request.toString()))
            .build();

        HttpResponse<String> response = httpClient.send(
            httpRequest,
            HttpResponse.BodyHandlers.ofString()
        );

        if (response.statusCode() != 200) {
            throw new Exception("MCP server returned status " + response.statusCode());
        }

        JSONObject jsonResponse = new JSONObject(response.body());
        return jsonResponse.getJSONArray("vulnerabilities");
    }

    /**
     * Test connection to MCP server
     *
     * @return true if server is reachable
     */
    public boolean testConnection() {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(mcpEndpoint + "/health"))
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();

            HttpResponse<String> response = httpClient.send(
                request,
                HttpResponse.BodyHandlers.ofString()
            );

            return response.statusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }
}
