export default {
  id: 'throwing-check',
  name: 'Throwing check',
  category: 'governance',
  weight: 10,

  async run(_context) {
    throw new Error('kaboom');
  },
};
