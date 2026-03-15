export default {
  id: 'mock-check',
  name: 'Mock check',
  category: 'governance',
  weight: 10,

  async run(_context) {
    return {
      score: 75,
      findings: [
        { severity: 'pass', title: 'Something good' },
        { severity: 'warning', title: 'Something iffy' },
      ],
    };
  },
};
