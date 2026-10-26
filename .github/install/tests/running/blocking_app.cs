// Фикстура блокирующего процесса для тестов установщика (Windows).
// Протокол ASCII: при старте печатает "READY:<marker>" и блокируется на stdin.
// Команда "version" -> "VERSION:<marker>", "exit" или EOF -> код 0.
// Ограничения C# компилятора .NET Framework / PowerShell 5.1 Add-Type:
// без интерполяции строк, async и новых версий языка.
using System;

public class BlockingFixture
{
    private const string FixtureVersion = "__FIXTURE_VERSION__";

    public static int Main()
    {
        Console.Out.Write("READY:" + FixtureVersion + "\n");
        Console.Out.Flush();

        while (true)
        {
            string line = Console.ReadLine();
            if (line == null)
            {
                return 0; // EOF
            }
            if (line == "version")
            {
                Console.Out.Write("VERSION:" + FixtureVersion + "\n");
                Console.Out.Flush();
            }
            else if (line == "exit")
            {
                return 0;
            }
        }
    }
}
