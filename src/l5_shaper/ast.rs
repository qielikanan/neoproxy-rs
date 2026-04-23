use rand::Rng;
use std::collections::HashMap;

pub struct ConnContext {
    pub rand_cache: HashMap<String, usize>,
}

impl ConnContext {
    pub fn new() -> Self {
        Self {
            rand_cache: HashMap::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum SizeNode {
    Fixed(usize),
    StartRand(usize),
    ConnRand {
        min: usize,
        max: usize,
        node_id: String,
    },
}

impl SizeNode {
    pub fn new_start_rand(min: usize, max: usize) -> Self {
        SizeNode::StartRand(random_int(min, max))
    }

    pub fn new_conn_rand(min: usize, max: usize, counter: usize) -> Self {
        SizeNode::ConnRand {
            min,
            max,
            node_id: format!("cr_{}", counter),
        }
    }

    pub fn eval(&self, ctx: &mut ConnContext) -> usize {
        match self {
            SizeNode::Fixed(val) => *val,
            SizeNode::StartRand(val) => *val,
            SizeNode::ConnRand { min, max, node_id } => {
                if let Some(&val) = ctx.rand_cache.get(node_id) {
                    val
                } else {
                    let val = random_int(*min, *max);
                    ctx.rand_cache.insert(node_id.clone(), val);
                    val
                }
            }
        }
    }
}

fn random_int(min: usize, max: usize) -> usize {
    if min >= max {
        return min;
    }
    rand::thread_rng().gen_range(min..=max)
}
