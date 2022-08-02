using SteamKit2;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;

namespace SteamKitAuth
{
    class Program
    {
        private string _loginUsername;
        private string _loginPassword;
        private string _loginAuthCode;
        private string _loginTwoFactorCode;
        private string _sentryFilePath;
        private uint _appId;
        private bool _no2FA;

        private bool _isRunning;
        private readonly SteamClient _steamClient;
        private readonly CallbackManager _callbackManager;
        private readonly SteamUser _steamUser;
        private readonly SteamAuthTicket _steamAuthTicket;

        private static void Main(string[] args)
        {
            Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);

            try
            {
                var self = new Program();
                self.LoadConfig();
                self.ParseArgs(args); // override
                self.Run();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            Environment.Exit(0);
        }

        public Program()
        {
            _steamClient = new SteamClient();
            _callbackManager = new CallbackManager(_steamClient);
            _steamUser = _steamClient.GetHandler<SteamUser>();

            _steamAuthTicket = new SteamAuthTicket();
            _steamClient.AddHandler(_steamAuthTicket);

            _callbackManager.Subscribe<SteamClient.DisconnectedCallback>(SteamClient_OnDisconnected);
            _callbackManager.Subscribe<SteamClient.ConnectedCallback>(SteamClient_OnConnected);

            _callbackManager.Subscribe<SteamUser.UpdateMachineAuthCallback>(SteamUser_OnUpdateMachineAuth);
            _callbackManager.Subscribe<SteamUser.LoggedOffCallback>(SteamUser_OnLoggedOff);
            _callbackManager.Subscribe<SteamUser.LoggedOnCallback>(SteamUser_OnLoggedOn);
        }

        private void LoadConfig()
        {
            if (File.Exists("SteamKitAuthConfig.txt") == false)
            {
                return;
            }

            foreach (var line in File.ReadAllLines("SteamKitAuthConfig.txt"))
            {
                var index = line.IndexOf('=');
                if (index == -1)
                {
                    continue;
                }

                var key = line.Substring(0, index);
                var value = line.Substring(index + 1);

                switch (key)
                {
                    case "USERNAME":
                        _loginUsername = value;
                        break;

                    case "PASSWORD":
                        _loginPassword = value;
                        break;

                    case "APPID":
                        uint.TryParse(value, out _appId);
                        break;
                }
            }
        }

        private void ParseArgs(string[] args)
        {
            for (var i = 0; i < args.Length; ++i)
            {
                switch (args[i])
                {
                    case "--username":
                        _loginUsername = args[++i];
                        break;

                    case "--password":
                        _loginPassword = args[++i];
                        break;

                    case "--app-id":
                        uint.TryParse(args[++i], out _appId);
                        break;

                    case "--no-2fa":
                        _no2FA = true;
                        break;
                }
            }
        }

        private void Run()
        {
            _sentryFilePath = $"sentry-{_loginUsername}.bin";
            _isRunning = true;

            Console.WriteLine("Connecting to Steam...");
            _steamClient.Connect();

            while (_isRunning)
            {
                _callbackManager.RunWaitCallbacks(TimeSpan.FromSeconds(1));
            }

            _steamClient.Disconnect();
        }

        private void SteamClient_OnDisconnected(SteamClient.DisconnectedCallback callback)
        {
            if (_isRunning == false)
            {
                return;
            }

            Console.WriteLine("Disconnected from Steam, reconnecting in 5...");
            Thread.Sleep(TimeSpan.FromSeconds(5));
            _steamClient.Connect();
        }

        private void SteamClient_OnConnected(SteamClient.ConnectedCallback callback)
        {
            Console.WriteLine("Connected to Steam! Logging in '{0}'...", _loginUsername);

            byte[] sentryFileHash = null;
            if (File.Exists(_sentryFilePath))
            {
                var sentryFile = File.ReadAllBytes(_sentryFilePath);
                sentryFileHash = CryptoHelper.SHAHash(sentryFile);
            }

            _steamUser.LogOn(new SteamUser.LogOnDetails()
            {
                Username = _loginUsername,
                Password = _loginPassword,
                AuthCode = _loginAuthCode,
                TwoFactorCode = _loginTwoFactorCode,
                SentryFileHash = sentryFileHash,
            });
        }

        private void SteamUser_OnUpdateMachineAuth(SteamUser.UpdateMachineAuthCallback callback)
        {
            Console.WriteLine("Updating sentryfile...");

            int fileSize;
            byte[] sentryFileHash;

            using (var stream = File.Open(_sentryFilePath, FileMode.OpenOrCreate, FileAccess.ReadWrite))
            {
                stream.Seek(callback.Offset, SeekOrigin.Begin);
                stream.Write(callback.Data, 0, callback.BytesToWrite);
                fileSize = (int)stream.Length;

                stream.Seek(0, SeekOrigin.Begin);
                using (var sha1 = SHA1.Create())
                {
                    sentryFileHash = sha1.ComputeHash(stream);
                }

                stream.Flush(true);
            }

            _steamUser.SendMachineAuthResponse(new SteamUser.MachineAuthDetails()
            {
                JobID = callback.JobID,
                Result = EResult.OK,
                BytesWritten = callback.BytesToWrite,
                Offset = callback.Offset,
                FileName = callback.FileName,
                FileSize = fileSize,
                LastError = 0,
                SentryFileHash = sentryFileHash,
                OneTimePassword = callback.OneTimePassword,
            });

            Console.WriteLine("Done!");
        }

        private void SteamUser_OnLoggedOff(SteamUser.LoggedOffCallback callback)
        {
            Console.WriteLine("Logged off of Steam: {0}", callback.Result);
        }

        private async void SteamUser_OnLoggedOn(SteamUser.LoggedOnCallback callback)
        {
            var isSteamGuard = callback.Result == EResult.AccountLogonDenied;
            var is2FA = callback.Result == EResult.AccountLoginDeniedNeedTwoFactor;

            if (isSteamGuard || is2FA)
            {
                Console.WriteLine("This account is SteamGuard protected!");

                if (_no2FA)
                {
                    _isRunning = false;
                    return;
                }

                if (is2FA)
                {
                    Console.Write("Please enter your 2 factor auth code from your authenticator app: ");
                    _loginTwoFactorCode = Console.ReadLine();
                }
                else
                {
                    Console.Write("Please enter the auth code sent to the email at {0}: ", callback.EmailDomain);
                    _loginAuthCode = Console.ReadLine();
                }

                return;
            }

            if (callback.Result != EResult.OK)
            {
                Console.WriteLine("Unable to logon to Steam: {0} / {1}", callback.Result, callback.ExtendedResult);
                _isRunning = false;
                return;
            }

            Console.WriteLine("Successfully logged on!");

            try
            {
                Console.WriteLine("GetAuthSessionTicket.. (AppID={0})", _appId);

                var ticketInfo = await _steamAuthTicket.GetAuthSessionTicket(_appId);
                var ticket = BitConverter.ToString(ticketInfo.Ticket).Replace("-", "");

                Console.WriteLine("Ticket={0}", ticket);
            }
            catch (Exception e)
            {
                Console.Write(e.ToString());
            }

            _isRunning = false;
        }
    }
}
