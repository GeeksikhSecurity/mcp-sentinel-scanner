use std::process::Command;
use std::path::Path;

const SECRET_KEY: &str = "sk-abcdef1234567890"; // Hardcoded secret

fn main() {
    let user_input = std::env::args().nth(1).unwrap();
    
    // Command injection
    Command::new("sh")
        .arg("-c")
        .arg(format!("echo {}", user_input))
        .output()
        .expect("failed");

    // Path traversal
    let dangerous_path = "../../../etc/passwd";
    let safe_path = Path::new("/safe").join(dangerous_path);
}

#[cfg(test)]
mod tests {
    const MOCK_API_KEY: &str = "test-key-123456789";
    
    #[test]
    fn test_something() {
        assert_eq!(2 + 2, 4);
    }
}