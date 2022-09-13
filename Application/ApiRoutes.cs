namespace Application
{
    /// <summary>
    /// route defenition for api
    /// </summary>
    public static class ApiRoutes
    {
        private const string RootUrl = "/api";

        /// <summary>
        /// autentication api route
        /// </summary>
        public static class Authentication
        {
            private const string Prefix = RootUrl + "/Authentication";
            public const string Register = Prefix + "/Register";
            public const string GetToken = Prefix + "/GetToken";
            public const string RefreshToken = Prefix + "/RefreshToken";
            public const string RevokeToken = Prefix + "/RevokeToken";
        }
    }
}
