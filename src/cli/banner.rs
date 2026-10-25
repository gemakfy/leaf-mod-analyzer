use super::style::Style;

pub fn print_banner(style: &Style) {
    println!("{}", style.green(" ██╗     ███████╗ █████╗ ███████╗"));
    println!("{}", style.green(" ██║     ██╔════╝██╔══██╗██╔════╝"));
    println!("{}", style.green(" ██║     █████╗  ███████║█████╗  "));
    println!("{}", style.green(" ██║     ██╔══╝  ██╔══██║██╔══╝  "));
    println!("{}", style.green(" ███████╗███████╗██║  ██║██║     "));
    println!("{}", style.green(" ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     "));
    println!(
        "{}",
        style.bold("  █▀▄▀█ █▀█ █▀▄   ▄▀█ █▄░█ ▄▀█ █░░ █▄█ ▀█ █▀▀ █▀█")
    );
    println!(
        "{}",
        style.bold("  █░▀░█ █▄█ █▄▀   █▀█ █░▀█ █▀█ █▄▄ ░█░ █▄ ██▄ █▀▄")
    );
    println!();
    println!(
        "   {} {}  {} {}",
        style.dim("Website:"),
        style.cyan("https://mods.merud.online/"),
        style.dim("•"),
        style.dim("Minecraft Mod & Cheat Scanner")
    );
    println!();
}
