using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Click2MoneyNext.Models.Exceptions;
using Click2MoneyNext.Models.Formatters;
using Click2MoneyNext.Models.Interfaces;
using Click2MoneyNext.Models.Users;
using Click2MoneyNext.Models.Validators;
using Dapper;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Education.Models.Services
{
    /// <summary>
    /// 
    /// </summary>
    public class UserService : IUserService
    {
        private readonly ILogger<UserService> _logger;
        private readonly NpgsqlConnection _connection;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="connection"></param>
        /// <param name="logger"></param>
        public UserService(NpgsqlConnection connection, ILogger<UserService> logger)
        {
            _connection = connection;
            _logger = logger;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="mail"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public async Task<long> CreateUser(string mail, string password, string telegram, string skype)
        {
            skype = skype?.Trim();
            telegram = TelegramFormatter.ReplaceRussiaToWorldCode(telegram);

            _logger.LogTrace($"Call CreateUser({mail}, ***, {telegram}, {skype})");

            if (!UserContactsValidator.IsValid(skype, telegram))
            {
                _logger.LogInformation($"Invalid contacts: [telegram: {telegram} ], [skype: {skype} ]");
                throw new InvalidRegistrationDataException();
            }

            var salt = CryptoTool.CreateSalt();
            var passwordHash = CryptoTool.Hash(password, salt);

            var newUser = new User
            {
                Mail = mail,
                PasswordSalt = Convert.ToBase64String(salt),
                PasswordHash = passwordHash,
                RegisterDate = DateTime.Now
            };

            const string queryStringInsertUser = @"
                                            INSERT INTO users (mail, password_hash, password_salt) VALUES (@Mail, @PasswordHash, @PasswordSalt)
                                                ON CONFLICT DO NOTHING
                                            RETURNING id                                            
                                            ";

            var response = await _connection.QueryAsync<long>(queryStringInsertUser, newUser);
            var newId = response.SingleOrDefault();

            if (newId == 0)
            {
                throw new UserAlreadyExistsException();
            }

            newUser.Id = newId;

            const string queryStringProfile = @"
                                        INSERT INTO user_profiles (user_id) VALUES (@Id);
                                        ";

            await _connection.QueryAsync(queryStringProfile, newUser);

            const string queryStringPayment = @"
                                        INSERT INTO user_payments_info (user_id) VALUES (@Id);
                                        ";

            await _connection.QueryAsync(queryStringPayment, newUser);


            List<UserContact> contacts = FillContacts(newId, skype, telegram);

            await AddContacts(contacts);

            return newId;
        }

        private List<UserContact> FillContacts(long userId, string skype, string telegram)
        {
            var contacts = new (string Name, string Value)[]
            {
                ("mobile", ""),
                ("skype", skype ?? ""),
                ("telegram", telegram ?? ""),
                ("vkontakte", ""),
                ("facebook", ""),
                ("searchengines", "")
            };

            var userContacts = new List<UserContact>();
            foreach (var contact in contacts)
            {
                userContacts.Add(new UserContact
                {
                    UserId = userId,
                    Name = contact.Name,
                    Value = contact.Value
                });
            }

            return userContacts;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="mail"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public async Task SetPassword(string mail, string password)
        {
            const string queryString = @"
                                 UPDATE users u set (password_hash,password_salt) = (@hash,@salt) WHERE u.mail=@mail
                                 ";

            var salt = CryptoTool.CreateSalt();
            var hash = CryptoTool.Hash(password, salt);

            await _connection.ExecuteAsync(queryString, new { hash, salt = Convert.ToBase64String(salt), mail });
        }

        /// <summary>
        /// CheckPassword
        /// </summary>
        /// <param name="mail"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public async Task<bool> CheckPassword(string mail, string password)
        {
            _logger.LogTrace($"Call CheckPassword({mail}, ***)");
            const string queryString = "SELECT * FROM users WHERE mail=@mail";
            var dbResult = (await _connection.QueryAsync<User>(queryString, new { mail })).ToList();

            if (dbResult.Count < 1)
                return false;

            var user = dbResult.First();
            var salt = Convert.FromBase64String(user.PasswordSalt);
            var realHash = user.PasswordHash;

            var tryHash = CryptoTool.Hash(password, salt);

            return tryHash == realHash;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public async Task Confirm(long userId)
        {
            const string queryString = @"UPDATE users SET (confirmed, confirmation_date) = (true, @date) WHERE id=@userId";
            await _connection.ExecuteAsync(queryString, new { userId, date = DateTime.UtcNow });
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public async Task Activate(long userId)
        {
            const string queryString = @"UPDATE users SET (active, activation_date) = (true, @date) WHERE id=@userId";
            await _connection.ExecuteAsync(queryString, new { userId, date = DateTime.UtcNow });
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public async Task Deactivate(long userId)
        {
            const string queryString = @"UPDATE users SET (active, activation_date) = (false, @date) WHERE id=@userId";
            await _connection.ExecuteAsync(queryString, new { userId, date = DateTime.UtcNow });
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userProfile"></param>
        /// <returns></returns>
        public async Task UpdateUserProfile(UserProfile userProfile)
        {
            const string queryStringProfile =
                @"
                UPDATE user_profiles
                    SET
                        ( first_name, last_name, picture, postback_link_id, timezone) =
                        (@FirstName, @LastName, @Picture, @PostbackLinkId, @TimeZone)
                WHERE user_id = @UserId;
                DELETE FROM user_contacts WHERE user_id=@UserId;";

            await _connection.ExecuteAsync(queryStringProfile, userProfile);

            foreach (var userProfileContact in userProfile.Contacts)
            {
                userProfileContact.UserId = userProfile.UserId;
            }

            await AddContacts(userProfile.Contacts);
        }

        private async Task AddContacts(List<UserContact> contacts)
        {
            const string queryStringContacts =
                @"INSERT INTO user_contacts (user_id, name, value) VALUES (@UserId, @Name, @Value)";

            await _connection.ExecuteAsync(queryStringContacts, contacts);
        }

        public async Task UpdateUserTimeZone(long userId, string TimeZone)
        {
            const string queryStringProfile =
                @"
                UPDATE user_profiles
                SET timezone = @TimeZone
                WHERE user_id = @UserId;";

            await _connection.ExecuteAsync(queryStringProfile, new { userId, TimeZone });
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userPaymentsInfo"></param>
        /// <returns></returns>
        public async Task UpdateUserPaymentInfo(UserPaymentInfo userPaymentsInfo)
        {
            const string queryString =
                @"Update user_payments_info
                    SET
                        ( wmr,  wmz,  bank_card, qiwi_wallet, yandex_money, bank_account) =
                        (@Wmr, @Wmz, @BankCard, @QiwiWallet, @YandexMoney, @BankAccount)
                    WHERE user_id = @UserId";

            await _connection.QueryAsync(queryString, userPaymentsInfo);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public async Task<UserPaymentInfo> GetUserPaymentInfo(long userId)
        {
            const string queryString =
                @"SELECT * FROM user_payments_info upi WHERE upi.user_id=@userId";

            return await _connection.QuerySingleAsync<UserPaymentInfo>(queryString, new { userId });
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public async Task<User> GetUserProfile(long userId)
        {
            const string queryString = @"
                SELECT
                        u.id,
                        u.mail,
                        u.register_date,
                        u.confirmation_date,
                        u.activation_date,
                        u.active,
                        u.confirmed,
                        u.percent,
                        profile.*,
                        uc.*
                    FROM users u
                    LEFT JOIN user_profiles profile on u.id = profile.user_id
                    LEFT JOIN user_contacts uc on u.id = uc.user_id
                WHERE u.id=@userId;
                ";

            User resultUser = null;

            await _connection.QueryAsync<User, UserProfile, UserContact, User>(queryString, (user, profile, contact) =>
            {
                if (resultUser == null)
                    resultUser = user;

                if (resultUser.Profile == null)
                    resultUser.Profile = profile;

                if (contact != null && !resultUser.Profile.Contacts.Exists(c => c.Name == contact.Name))
                {
                    resultUser.Profile.Contacts.Add(contact);
                }

                return user;
            }, new { userId });

            return resultUser;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userMail"></param>
        /// <returns></returns>
        public async Task<User> GetFullUser(string userMail)
        {
            const string queryString = @"
                SELECT * FROM users u
                WHERE u.mail=@userMail;
                ";

            var result = await _connection.QuerySingleOrDefaultAsync<User>(queryString, new { userMail });

            if (result == null)
                return null;

            result = await FullUpUser(result);

            return result;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public async Task<User> GetFullUser(long userId)
        {
            const string queryString = @"
                SELECT * FROM users u
                WHERE u.id=@userId;
                ";

            var result = await _connection.QuerySingleOrDefaultAsync<User>(queryString, new { userId });

            if (result == null)
                return null;

            result = await FullUpUser(result);

            return result;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private async Task<User> FullUpUser(User user)
        {
            var userProfile = await GetUserProfile(user.Id);
            user.Profile = userProfile.Profile;

            var roles = await GetUserRoles(user.Id);
            user.Roles = roles;

            var paymentInfo = await GetUserPaymentInfo(user.Id);
            user.PaymentInfo = paymentInfo;

            return user;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public async Task<List<Role>> GetUserRoles(long userId)
        {
            const string queryString = @"
                 SELECT r.* FROM  user_role ur
                    LEFT JOIN roles r on ur.role_id = r.id
                WHERE ur.user_id=@userId;
                ";

            var result = await _connection.QueryAsync<Role>(queryString, new { userId });

            return result.ToList();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public async Task UpdatePercent(UpdatePercentModel user)
        {
            const string queryStringProfile = "UPDATE users SET percent = @Percent WHERE id = @UserId;";

            await _connection.ExecuteAsync(queryStringProfile, user);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userMail"></param>
        /// <param name="roles"></param>
        /// <returns></returns>
        public async Task SetUserRoles(string userMail, List<string> roles)
        {
            await _connection.ExecuteTransaction(async transaction =>
            {

                const string queryString = @"
                DELETE FROM user_role WHERE user_id=(SELECT u.id from users u WHERE u.mail=@userMail);
                INSERT INTO
                    user_role (user_id, role_id)
                SELECT u.id, r.id FROM roles r
                    CROSS JOIN users u
                    WHERE u.mail=@userMail AND r.name= ANY( @roles )
                ";

                await _connection.QueryAsync(queryString, new { userMail, roles }, transaction);

                return true;
            });
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userMail"></param>
        /// <param name="role"></param>
        /// <returns></returns>
        public async Task AddUserRole(string userMail, string role)
        {
            const string queryString = @"
                INSERT INTO
                    user_role (user_id, role_id)
                SELECT u.id, r.id FROM roles r
                    CROSS JOIN users u
                    WHERE u.mail=@userMail AND r.name= @role
                ON CONFLICT DO NOTHING 
                ";

            await _connection.QueryAsync(queryString, new { userMail, role });
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userMail"></param>
        /// <param name="role"></param>
        /// <returns></returns>
        public async Task RemoveUserRole(string userMail, string role)
        {
            const string queryString = @"
                DELETE FROM user_role
                    WHERE
                        user_id= (SELECT u.id from users u WHERE u.mail=@userMail)
                    AND
                        role_id = (SELECT r.id from roles r WHERE r.name=@role)
                ";

            await _connection.QueryAsync(queryString, new { userMail, role });
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="role"></param>
        /// <returns></returns>
        public async Task AddUserRole(long userId, string role)
        {
            const string queryString = @"
                INSERT INTO
                    user_role (user_id, role_id)
                SELECT u.id, r.id FROM roles r
                    CROSS JOIN users u
                    WHERE u.id=@userId AND r.name= @role
                ON CONFLICT DO NOTHING 
                ";

            await _connection.QueryAsync(queryString, new { userId, role });
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="role"></param>
        /// <returns></returns>
        public async Task RemoveUserRole(long userId, string role)
        {
            const string queryString = @"
                DELETE FROM user_role
                    WHERE
                        user_id=@userId
                    AND
                        role_id = (SELECT r.id from roles r WHERE r.name=@role)
                ";

            await _connection.QueryAsync(queryString, new { userId, role });
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public async Task SaveToken(UserConfirmationToken token)
        {
            const string queryString = @"
                    INSERT INTO user_confirmation_tokens (token, type, user_id, valid_through) VALUES (@Token, @Type, @UserId, @ValidThrough)";

            await _connection.ExecuteAsync(queryString, token);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <param name="userId"></param>
        /// <param name="type"></param>
        /// <returns></returns>
        public async Task<UserConfirmationToken> GetToken(string token, long userId, UserConfirmationTokenType type)
        {
            const string queryString = @"
                    DELETE FROM user_confirmation_tokens WHERE token=@token AND type=@Type AND user_id=@userId RETURNING *";

            return await _connection.QueryFirstOrDefaultAsync<UserConfirmationToken>(queryString, new { token, userId, type });
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <param name="type"></param>
        /// <returns></returns>
        public async Task<UserConfirmationToken> GetToken(string token, UserConfirmationTokenType type)
        {
            const string queryString = @"
                    DELETE FROM user_confirmation_tokens WHERE token=@token AND type=@Type RETURNING *";

            return await _connection.QueryFirstOrDefaultAsync<UserConfirmationToken>(queryString, new { token, type });
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public async Task<Page<User>> ListUsers(Filter filter)
        {
            if (filter == null)
            {
                filter = new Filter();

                filter.ItemsPerPage = 1000;

                //filter.SortColumn = "register_date";
            }

            string queryString = @"
                SELECT  u.id,
                        u.mail,
                        u.confirmed,
                        u.active,
                        u.register_date,
                        u.activation_date,
                        u.confirmation_date,
                        u.percent
                        , count(*) OVER() AS full_count
                    FROM users u
                WHERE 1=1 /**where**/
                ORDER BY register_date DESC
                LIMIT @ItemsPerPage OFFSET @offset
                ";

            if (!string.IsNullOrEmpty(filter.Search))
            {
                queryString = queryString.Replace("/**where**/", string.Format(" AND CAST(u.id AS TEXT) ILIKE '%{0}%' or u.mail ILIKE '%{0}%'", filter.Search));
            }

            Page<User> result = new Page<User>();
            result.Items = (await _connection.QueryAsync<User, long, User>(queryString,
                (user, count) =>
                {
                    result.ItemsCount = count;
                    return user;
                },
                new { filter.Offset, filter.ItemsPerPage, filter.SortColumnWithDirection },
                    splitOn: "id, full_count")).ToList();

            return result;
        }

        public async Task<Click2MoneyNext.Models.Users.TimeZone> GetUserTimeZone(long userId)
        {
            const string queryString = @"SELECT tn.name, tn.abbrev, tn.utc_offset, tn.is_dst FROM user_profiles up LEFT JOIN pg_timezone_names tn ON up.timezone = tn.name WHERE up.user_id=@userId;";

            var result = (await _connection.QueryAsync<Click2MoneyNext.Models.Users.TimeZone>(queryString, new { userId })).FirstOrDefault(); ;

            return result;
        }

        public async Task<Click2MoneyNext.Models.Users.TimeZone> GetTimeZone(string name)
        {
            const string queryString = @"select * from select_pg_timezone(@name);";

            return (await _connection.QueryAsync<Click2MoneyNext.Models.Users.TimeZone>(queryString, new { name })).FirstOrDefault();
        }
    }
}
