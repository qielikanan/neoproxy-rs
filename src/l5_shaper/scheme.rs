use super::ast::{ConnContext, SizeNode};

#[derive(Clone, Debug, PartialEq)]
pub enum ActionType {
    SendData, // 发送业务数据
    Inject,   // 注入干扰帧
    Done,     // 当前策略完毕，转为全速透传
}

#[derive(Clone, Debug)]
pub struct SplitInst {
    pub sizes: Vec<SizeNode>,
}

#[derive(Clone, Debug)]
pub struct InjectInst {
    pub size: SizeNode,
}

#[derive(Clone, Debug)]
pub enum Instruction {
    Split(SplitInst),
    Inject(InjectInst),
}

/// 编译后的 AST 树
#[derive(Clone, Debug)]
pub struct Scheme {
    pub instructions: Vec<Instruction>,
}

pub struct SchemeIterator {
    scheme: Scheme,
    inst_idx: usize,
    current_part: usize,
}

impl SchemeIterator {
    pub fn new(scheme: Scheme) -> Self {
        Self {
            scheme,
            inst_idx: 0,
            current_part: 0,
        }
    }

    pub fn next_action(&mut self, ctx: &mut ConnContext) -> (ActionType, usize) {
        if self.inst_idx >= self.scheme.instructions.len() {
            return (ActionType::Done, 0);
        }

        match &self.scheme.instructions[self.inst_idx] {
            Instruction::Split(inst) => {
                if self.current_part >= inst.sizes.len() {
                    self.inst_idx += 1;
                    self.current_part = 0;
                    return self.next_action(ctx);
                }
                let length = inst.sizes[self.current_part].eval(ctx);
                self.current_part += 1;
                (ActionType::SendData, length)
            }
            Instruction::Inject(inst) => {
                if self.current_part >= 1 {
                    self.inst_idx += 1;
                    self.current_part = 0;
                    return self.next_action(ctx);
                }
                let length = inst.size.eval(ctx);
                self.current_part += 1;
                (ActionType::Inject, length)
            }
        }
    }
}
