use super::ast::SizeNode;
use super::scheme::{InjectInst, Instruction, Scheme, SplitInst};
use anyhow::{anyhow, Result};

#[derive(Debug, PartialEq, Clone)]
enum TokenType {
    EOF,
    Ident(String),
    Number(usize),
    LParen,
    RParen,
    Comma,
    Semi,
}

fn tokenize(script: &str) -> Vec<TokenType> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = script.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }

        if c.is_alphabetic() {
            let start = i; // 修复了未使用 mut 的警告
            while i < chars.len() && (chars[i].is_alphanumeric()) {
                i += 1;
            }
            tokens.push(TokenType::Ident(chars[start..i].iter().collect()));
            continue;
        }

        if c.is_ascii_digit() {
            let start = i; // 修复了未使用 mut 的警告
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let num_str: String = chars[start..i].iter().collect();
            tokens.push(TokenType::Number(num_str.parse().unwrap_or(0)));
            continue;
        }

        match c {
            '(' => tokens.push(TokenType::LParen),
            ')' => tokens.push(TokenType::RParen),
            ',' => tokens.push(TokenType::Comma),
            ';' => tokens.push(TokenType::Semi),
            _ => {}
        }
        i += 1;
    }

    tokens.push(TokenType::EOF);
    tokens
}

struct Parser {
    tokens: Vec<TokenType>,
    pos: usize,
    counter: usize,
}

impl Parser {
    fn peek(&self) -> TokenType {
        self.tokens.get(self.pos).cloned().unwrap_or(TokenType::EOF)
    }

    fn next(&mut self) -> TokenType {
        let tok = self.peek();
        self.pos += 1;
        tok
    }

    fn expect(&mut self, expected: TokenType) -> Result<()> {
        let tok = self.next();
        if std::mem::discriminant(&tok) != std::mem::discriminant(&expected) {
            return Err(anyhow!("Unexpected token: {:?}", tok));
        }
        Ok(())
    }

    fn parse_instruction(&mut self) -> Result<Instruction> {
        let ident = match self.next() {
            TokenType::Ident(name) => name.to_lowercase(),
            tok => return Err(anyhow!("Expected instruction name, got {:?}", tok)),
        };

        self.expect(TokenType::LParen)?;

        match ident.as_str() {
            "split" => {
                let sizes = self.parse_size_list()?;
                self.expect(TokenType::RParen)?;
                Ok(Instruction::Split(SplitInst { sizes }))
            }
            "fixed" => {
                let size = self.parse_size_node()?;
                self.expect(TokenType::RParen)?;
                Ok(Instruction::Split(SplitInst { sizes: vec![size] }))
            }
            "inject" => {
                let size = self.parse_size_node()?;
                self.expect(TokenType::RParen)?;
                Ok(Instruction::Inject(InjectInst { size }))
            }
            _ => Err(anyhow!("Unknown instruction: {}", ident)),
        }
    }

    fn parse_size_list(&mut self) -> Result<Vec<SizeNode>> {
        let mut sizes = Vec::new();
        loop {
            sizes.push(self.parse_size_node()?);
            if matches!(self.peek(), TokenType::Comma) {
                self.next();
            } else {
                break;
            }
        }
        Ok(sizes)
    }

    fn parse_size_node(&mut self) -> Result<SizeNode> {
        let tok = self.next();
        match tok {
            TokenType::Number(val) => Ok(SizeNode::Fixed(val)),
            TokenType::Ident(name) => {
                self.expect(TokenType::LParen)?;

                let min = match self.next() {
                    TokenType::Number(n) => n,
                    _ => return Err(anyhow!("Expected min number")),
                };

                self.expect(TokenType::Comma)?;

                let max = match self.next() {
                    TokenType::Number(n) => n,
                    _ => return Err(anyhow!("Expected max number")),
                };

                self.expect(TokenType::RParen)?;

                let node_name = name.to_lowercase();
                match node_name.as_str() {
                    "startrand" => Ok(SizeNode::new_start_rand(min, max)),
                    "connrand" => {
                        self.counter += 1;
                        Ok(SizeNode::new_conn_rand(min, max, self.counter))
                    }
                    _ => Err(anyhow!("Unknown function: {}", node_name)),
                }
            }
            _ => Err(anyhow!("Expected number or rand function, got {:?}", tok)),
        }
    }
}

pub fn parse_script(script: &str) -> Result<Scheme> {
    let tokens = tokenize(script);
    let mut parser = Parser {
        tokens,
        pos: 0,
        counter: 0,
    };
    let mut scheme = Scheme {
        instructions: Vec::new(),
    };

    while !matches!(parser.peek(), TokenType::EOF) {
        if matches!(parser.peek(), TokenType::Semi) {
            parser.next();
            continue;
        }

        let inst = parser.parse_instruction()?;
        scheme.instructions.push(inst);

        if matches!(parser.peek(), TokenType::Semi) {
            parser.next();
        } else if !matches!(parser.peek(), TokenType::EOF) {
            return Err(anyhow!("Expected ';' or EOF"));
        }
    }

    Ok(scheme)
}
