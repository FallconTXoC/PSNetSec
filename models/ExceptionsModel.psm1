class CustomRestException : Exception {
    [int] $StatusCode

    CustomRestException($Message, $statusCode) : base($Message) {
        $this.StatusCode = $statusCode
    }
}