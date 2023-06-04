using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

internal class PasswordManager
{
    private static string passwordHashFile = "passwordHash.txt";
    private static string passwordFile = "passwords.txt";

    static void Main()
    {
        Console.WriteLine("Password Manager");
        Console.WriteLine("----------------");

        if (!File.Exists(passwordHashFile))
        {
            Console.SetWindowSize(Console.WindowWidth, Console.WindowHeight);
            Console.Write("Create a master password: ");
            string masterPassword = Console.ReadLine();
            string passwordHash = HashPassword(masterPassword);

            File.WriteAllText(passwordHashFile, passwordHash);

            Console.WriteLine("Master password created successfully.");
        }
        Console.Clear();
        Console.SetWindowSize(Console.WindowWidth, Console.WindowHeight);
        Console.Write("Enter master password: ");
        string enteredPassword = Console.ReadLine();
        string storedPasswordHash = File.ReadAllText(passwordHashFile);

        if (VerifyPassword(enteredPassword, storedPasswordHash))
        {
            Console.WriteLine("Access granted.");
            Console.WriteLine();

            while (true)
            {
                Console.Write("Press any Key to continue");
                Console.ReadKey();
                Console.Clear();
                Console.WriteLine("1. Show passwords");
                Console.WriteLine("2. Add password");
                Console.WriteLine("3. Change master password");
                Console.WriteLine("4. Remove all Passwords") ;
                Console.WriteLine("5. Exit");

                Console.Write("Enter your choice: ");
                string choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        ShowPasswords();
                        break;
                    case "2":
                        AddPassword();
                        break;
                    case "3":
                        Console.Clear();
                        Console.Write("Enter old Password: ");
                        ChangePasswd(Console.ReadLine());
                        break;
                    case "4":
                        File.Delete(passwordHashFile);
                        break;
                    case "5":
                        Environment.Exit(0);
                        break;
                    default:
                        Console.WriteLine("Invalid choice. Please try again.");
                        break;
                }

                Console.WriteLine();
            }
        }
        else
        {
            Console.WriteLine("Access denied. Incorrect master password.");

        }
    }

    static void ShowPasswords()
    {
        if (!File.Exists(passwordFile))
        {
            Console.WriteLine("No passwords found.");
            return;
        }

        Console.WriteLine("Passwords:");
        Console.WriteLine("----------");

        string encryptedPasswords = File.ReadAllText(passwordFile);

        string decryptedPasswords = Decrypt(encryptedPasswords, GetEncryptionKey());

        string[] passwordEntries = decryptedPasswords.Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);

        foreach (string entry in passwordEntries)
        {
            string[] parts = entry.Split(':');
            string website = parts[0];
            string username = parts[1];
            string password = parts[2];

            Console.WriteLine($"Website: {website}");
            Console.WriteLine($"Username: {username}");
            Console.WriteLine($"Password: {password}");
            Console.WriteLine();
        }
    }

    static void AddPassword()
    {
        Console.Write("Enter website: ");
        string website = Console.ReadLine();

        Console.Write("Enter username: ");
        string username = Console.ReadLine();

        Console.Write("Enter password: ");
        string password = Console.ReadLine();

        string entry = $"{website}:{username}:{password}{Environment.NewLine}";

        if (!File.Exists(passwordFile))
        {
            File.WriteAllText(passwordFile, Encrypt(entry, GetEncryptionKey()));
        }
        else
        {
            string encryptedPasswords = File.ReadAllText(passwordFile);
            string decryptedPasswords = Decrypt(encryptedPasswords, GetEncryptionKey());

            decryptedPasswords += entry;

            File.WriteAllText(passwordFile, Encrypt(decryptedPasswords, GetEncryptionKey()));
        }

        Console.WriteLine("Password added successfully.");
    }

    static string GetEncryptionKey()
    {
        string storedPasswordHash = File.ReadAllText(passwordHashFile);
        string hashedPassword = HashPassword(storedPasswordHash);

        // Truncate or pad the hashed password to 32 bytes (256 bits)
        byte[] keyBytes = new byte[32];
        Buffer.BlockCopy(Encoding.UTF8.GetBytes(hashedPassword), 0, keyBytes, 0, keyBytes.Length);

        return Convert.ToBase64String(keyBytes);
    }


    static string Encrypt(string plainText, string key)
    {
        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
        using (var aes = Aes.Create())
        {
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Key = Encoding.UTF8.GetBytes(key).Take(32).ToArray();
            aes.IV = Encoding.UTF8.GetBytes(key).Take(16).ToArray();

            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    byte[] cipherBytes = memoryStream.ToArray();
                    return Convert.ToBase64String(cipherBytes);
                }
            }
        }
    }

    static string Decrypt(string cipherText, string key)
    {
        byte[] cipherBytes = Convert.FromBase64String(cipherText);
        using (var aes = Aes.Create())
        {
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Key = Encoding.UTF8.GetBytes(key).Take(32).ToArray();
            aes.IV = Encoding.UTF8.GetBytes(key).Take(16).ToArray();

            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(cipherBytes, 0, cipherBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    byte[] plainBytes = memoryStream.ToArray();
                    return Encoding.UTF8.GetString(plainBytes);
                }
            }
        }
    }


    static string HashPassword(string password)
    {
        using (var sha256 = SHA256.Create())
        {
            byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(hashBytes);
        }
    }

    static bool VerifyPassword(string password, string passwordHash)
    {
        string hashedPassword = HashPassword(password);
        return (hashedPassword == passwordHash);
    }

    static void ChangePasswd(string oldPasswd)
    {
        if (VerifyPassword(oldPasswd, File.ReadAllText(passwordHashFile)))
        {
            Console.WriteLine();
            Console.Write("New Password: ");
            string newpasswdenter = Console.ReadLine();
            //File.Delete(passwordHashFile);
            //Thread.Sleep(500);
            File.Create(passwordHashFile);
            File.WriteAllText(passwordHashFile, HashPassword(newpasswdenter));
            Console.WriteLine("Successfully changed Master Password!");
            return;
        }
        else { Console.WriteLine("Wrong Passwd!"); return; }
    }
}
