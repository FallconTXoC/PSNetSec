using module '.\ExceptionsModel.psm1'

class RestModel {
    <#
        Performs GET request on given URL.
        @param [string] $url      - URL to request
        @param [object] $headers  - Headers to add to the request
        @return [object] Request result
    #>
    static [object] GetRequest([string]$url, [object]$headers) {
        try {
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
            return $response
        } catch {         
            throw [CustomRestException]::new("Error while performing GET request on $url. ($_)", $_.Exception.Response.StatusCode.value__)
        }
    }
	
	<#
		Performs GET request on given URL.
		@param [string] $url      - URL to request
		@param [object] $headers  - Headers to add to the request
		@return [object] Request result
    #>
    static [object] GetRequestWithCreds([string]$url, [object]$headers, [PSCredential]$creds) {
        try {
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -Credential $creds
            return $response
        } catch {         
            throw [CustomRestException]::new("Error while performing GET request on $url. ($_)", $_.Exception.Response.StatusCode.value__)
        }
    }

    <#
        Performs CUD request (CREATE/UPDATE/DELETE).
        @param [string] $url      - URL to request
        @param [object] $headers  - Headers to add to the request
        @param [string] $method   - Method to use for the request
        @param [object] $body     - Body of the request
        @return [object] Request result
    #>
    static [object] CUDRequest([string]$url, [Hashtable]$headers, [string]$method, [Hashtable]$body) {
        $jsonPostParams = $body | ConvertTo-Json -Depth 100
        $headers["Content-Type"] = "application/json"

        try {
            $result = Invoke-RestMethod -Uri $url -Headers $headers -Method $method -Body $jsonPostParams
            return $result
        } catch {         
            throw [CustomRestException]::new("Error while performing $method request on $url. ($_)", $_.Exception.Response.StatusCode.value__)
        }
    }
}