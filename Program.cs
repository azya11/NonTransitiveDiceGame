using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Spectre.Console;

namespace NonTransitiveDiceGame
{
    // ============================ DOMAIN ============================
    public sealed class Die
    {
        private readonly int[] _faces;
        public IReadOnlyList<int> Faces => _faces;
        public int Sides => _faces.Length;
        public Die(IEnumerable<int> faces)
        {
            _faces = faces.ToArray();
            if (_faces.Length == 0)
                throw new ArgumentException("A die must have at least one face.");
        }
        public int this[int index] => _faces[index];
        public override string ToString() => string.Join(',', _faces);
    }

    // ======================= PARSING & VALIDATION ===================
    public static class DiceSetParser
    {
        public static IReadOnlyList<Die> Parse(string[] args)
        {
            if (args.Length < 3)
                throw new UserInputException("You must specify at least three dice.",
                    "Example: game.exe 2,2,4,4,9,9 6,8,1,1,8,6 7,5,3,7,5,3");

            var dice = new List<Die>();
            int? sidesExpected = null;
            foreach (var arg in args)
            {
                var parts = arg.Split(',', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 0)
                    throw new UserInputException($"Die '{arg}' has no faces.");
                var faces = new List<int>();
                foreach (var p in parts)
                {
                    if (!int.TryParse(p, out var v))
                        throw new UserInputException($"Value '{p}' in die '{arg}' is not an integer.");
                    faces.Add(v);
                }
                sidesExpected ??= faces.Count;
                if (faces.Count != sidesExpected.Value)
                    throw new UserInputException("All dice must have the same number of sides.");
                dice.Add(new Die(faces));
            }
            return dice;
        }
    }

    public class UserInputException : Exception
    {
        public string? Example { get; }
        public UserInputException(string message, string? example = null) : base(message) => Example = example;
    }

    // =========================== CRYPTO ============================
    public static class SecureRng
    {
        private static readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();
        public static int NextInt(int exclusiveMax)
        {
            if (exclusiveMax <= 0) throw new ArgumentOutOfRangeException(nameof(exclusiveMax));
            int mask = ((int)BitOperations.RoundUpToPowerOf2((uint)exclusiveMax)) - 1;
            Span<byte> buffer = stackalloc byte[4];
            while (true)
            {
                _rng.GetBytes(buffer);
                int val = BitConverter.ToInt32(buffer);
                val &= mask;
                if (val < exclusiveMax) return val;
            }
        }
        public static byte[] RandomBytes(int length)
        {
            var b = new byte[length];
            _rng.GetBytes(b);
            return b;
        }
    }

    public static class HmacHelper
    {
        public static byte[] ComputeSha3(byte[] key, int message)
        {
            // message as 4-byte little-endian for simplicity
            Span<byte> msg = stackalloc byte[4];
            BitConverter.TryWriteBytes(msg, message);
            var msgBytes = BitConverter.GetBytes(message);
            // In .NET 8+, we could use HMAC<SHA3_256> but it's not yet in BCL; rely on BouncyCastle.
            var digest = new Sha3Digest(256);
            var hmac = new HMac(digest);
            hmac.Init(new KeyParameter(key));
            hmac.BlockUpdate(msgBytes, 0, msg.Length);
            var outBuf = new byte[digest.GetDigestSize()];
            hmac.DoFinal(outBuf, 0);
            return outBuf;
        }
        public static string ToHex(byte[] bytes) => Convert.ToHexString(bytes);
    }

    // =============== FAIR RANDOM GENERATION PROTOCOL ===============
    public class FairRandomProtocol
    {
        private readonly int _rangeInclusive;
        public FairRandomProtocol(int rangeInclusive) => _rangeInclusive = rangeInclusive;

        public int Execute(string prompt)
        {
            int rangeSize = _rangeInclusive + 1;
            // 1-2. Computer picks x and secret key
            int x = SecureRng.NextInt(rangeSize);
            byte[] key = SecureRng.RandomBytes(32); // 256-bit
            byte[] hmac = HmacHelper.ComputeSha3(key, x);
            AnsiConsole.MarkupLine($"[yellow]{prompt}[/]");
            AnsiConsole.MarkupLine($"I selected a random value in the range 0..{_rangeInclusive} (HMAC={HmacHelper.ToHex(hmac)}).\n");

            // 4. User selects y
            int y = MenuRenderer.ReadNumber(rangeSize, "Add your number");

            // 5. Calculate result
            int result = (x + y) % rangeSize;

            // 6. Reveal
            AnsiConsole.MarkupLine($"My number is {x} (KEY={HmacHelper.ToHex(key)}).\nThe fair number generation result is {x} + {y} = {result} (mod {rangeSize}).\n");
            return result;
        }
    }

    // ===================== PROBABILITIES ===========================
    public static class ProbabilityCalculator
    {
        public static double WinProbability(Die user, Die opponent)
        {
            int wins = 0, total = user.Sides * opponent.Sides;
            foreach (var uf in user.Faces)
                foreach (var of in opponent.Faces)
                    if (uf > of) wins++;
            return (double)wins / total;
        }
    }

    public static class ProbabilityTable
    {
        public static double[,] Build(IReadOnlyList<Die> dice)
        {
            int n = dice.Count;
            var table = new double[n, n];
            for (int i = 0; i < n; i++)
                for (int j = 0; j < n; j++)
                    table[i, j] = ProbabilityCalculator.WinProbability(dice[i], dice[j]);
            return table;
        }
    }

    // ========================= UI HELPERS ==========================
    public static class TableRenderer
    {
        public static void Render(double[,] probs, IReadOnlyList<Die> dice)
        {
            var grid = new Table().Border(TableBorder.Square);
            grid.AddColumn(new TableColumn("[bold]User dice ↓ vs >[/]").Centered());
            foreach (var die in dice)
                grid.AddColumn(new TableColumn($"[blue]{die}[/]").Centered());

            for (int i = 0; i < dice.Count; i++)
            {
                var row = new List<string> { $"[blue]{dice[i]}[/]" };
                for (int j = 0; j < dice.Count; j++)
                {
                    if (i == j)
                        row.Add("-");
                    else
                        row.Add($"{probs[i, j]:0.000}");
                }
                grid.AddRow(row.ToArray());
            }
            AnsiConsole.Write(grid);
        }
    }

    public static class MenuRenderer
    {
        public static int ReadNumber(int rangeSize, string? header = null)
        {
            while (true)
            {
                if (header != null) AnsiConsole.MarkupLine($"{header} (0-{rangeSize - 1}, X exit): ");
                string? input = Console.ReadLine();
                if (input == null) continue;
                if (input.Equals("X", StringComparison.OrdinalIgnoreCase)) Environment.Exit(0);
                if (int.TryParse(input, out int val) && val >= 0 && val < rangeSize)
                    return val;
                AnsiConsole.MarkupLine("[red]Invalid selection.[/]");
            }
        }

        public static int SelectDie(IReadOnlyList<Die> dice, string actor)
        {
            while (true)
            {
                AnsiConsole.MarkupLine($"Choose your die, {actor}:\n");
                for (int i = 0; i < dice.Count; i++)
                    AnsiConsole.MarkupLine($"{i} - {dice[i]}");
                AnsiConsole.MarkupLine("X - exit\n? - help");
                string? choice = Console.ReadLine();
                if (choice == null) continue;
                if (choice.Equals("X", StringComparison.OrdinalIgnoreCase)) Environment.Exit(0);
                if (choice == "?")
                {
                    var table = ProbabilityTable.Build(dice);
                    TableRenderer.Render(table, dice);
                    continue;
                }
                if (int.TryParse(choice, out int idx) && idx >= 0 && idx < dice.Count)
                    return idx;
                AnsiConsole.MarkupLine("[red]Invalid selection.[/]");
            }
        }
    }

    // ======================== GAME ENGINE ==========================
    public class GameEngine
    {
        private readonly IReadOnlyList<Die> _dice;
        public GameEngine(IReadOnlyList<Die> dice) => _dice = dice;

        public void Run()
        {
            // Determine who picks first (0=user,1=computer)
            var firstChooser = new FairRandomProtocol(1).Execute("Let's determine who makes the first move.");
            bool userFirst = firstChooser == 0;
            AnsiConsole.MarkupLine(userFirst ? "You make the first move." : "I make the first move.");

            int userDieIdx, compDieIdx;
            if (userFirst)
            {
                userDieIdx = MenuRenderer.SelectDie(_dice, "user");
                compDieIdx = SecureRng.NextInt(_dice.Count - 1);
                if (compDieIdx >= userDieIdx) compDieIdx++; // ensure different
            }
            else
            {
                compDieIdx = SecureRng.NextInt(_dice.Count);
                userDieIdx = MenuRenderer.SelectDie(_dice.Where((_, i) => i != compDieIdx).ToList(), "user");
                // adjust selected index
                if (userDieIdx >= compDieIdx) userDieIdx++;
            }

            var userDie = _dice[userDieIdx];
            var compDie = _dice[compDieIdx];

            AnsiConsole.MarkupLine($"You chose [green]{userDie}[/]. I chose [red]{compDie}[/].\n");

            // Roll user die (user participates)
            int userIndex = new FairRandomProtocol(userDie.Sides - 1).Execute("It's time for your roll.");
            int userRoll = userDie[userIndex];
            AnsiConsole.MarkupLine($"Your roll result is {userRoll}.");

            // Roll computer die (user participates)
            int compIndex = new FairRandomProtocol(compDie.Sides - 1).Execute("It's time for my roll.");
            int compRoll = compDie[compIndex];
            AnsiConsole.MarkupLine($"My roll result is {compRoll}.");

            if (userRoll > compRoll) AnsiConsole.MarkupLine("[green]You win![/]");
            else if (userRoll < compRoll) AnsiConsole.MarkupLine("[red]I win![/]");
            else AnsiConsole.MarkupLine("[yellow]It's a draw.[/]");
        }
    }

    // =========================== ENTRY =============================
    public static class Program
    {
        public static void Main(string[] args)
        {
            try
            {
                var dice = DiceSetParser.Parse(args);
                var engine = new GameEngine(dice);
                engine.Run();
            }
            catch (UserInputException ex)
            {
                AnsiConsole.MarkupLine($"[red]{ex.Message}[/]");
                if (!string.IsNullOrWhiteSpace(ex.Example))
                    AnsiConsole.MarkupLine($"Example: {ex.Example}");
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]Unexpected error: {ex.Message}[/]");
            }
        }
    }
}