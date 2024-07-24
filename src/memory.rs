pub struct Memory {
    byte_array: Vec<u8>,
}
impl Memory {
    pub fn new() -> Memory {
        Memory {
            byte_array: Vec::new(),
        }
    }
    pub fn msize(&self) -> usize {
        assert!(self.byte_array.len() % 32 == 0);
        return self.byte_array.len();
    }
    fn expand_memory_if_required(&mut self, offset: usize, size: usize) {
        let words = self.byte_array.len() / 32;
        let new_words = ((offset + size) / 32) + (if ((offset + size) % 32) > 0 { 1 } else { 0 });
        if new_words - words > 0 {
            self.byte_array.resize(new_words * 32, 0);
        }
    }
    pub fn store(&mut self, offset: usize, value: &Vec<u8>) {
        self.expand_memory_if_required(offset, value.len());
        for i in offset..self.byte_array.len() {
            if i - offset >= value.len() {
                break;
            }
            self.byte_array[i] = value[i - offset];
        }
    }

    pub fn load(&mut self, offset: usize, size: usize) -> Vec<u8> {
        self.expand_memory_if_required(offset, size);
        let mut ans: Vec<u8> = Vec::new();
        for x in offset..(offset + size) {
            ans.push(self.byte_array[x]);
        }
        ans
    }
}
