// Manual Cholesky decomposition - paste this into index.js after boxMuller()
choleskyDecomp(matrix) {
  const n = matrix.length;
  const L = Array(n).fill(0).map(() => Array(n).fill(0));

  for (let i = 0; i < n; i++) {
    for (let j = 0; j <= i; j++) {
      let sum = 0;

      if (i === j) {
        for (let k = 0; k < j; k++) {
          sum += L[j][k] ** 2;
        }
        const val = matrix[j][j] - sum;
        if (val <= 0) {
          throw new Error(\`Matrix is not positive definite at position [\${j},\${j}]\`);
        }
        L[j][j] = Math.sqrt(val);
      } else {
        for (let k = 0; k < j; k++) {
          sum += L[i][k] * L[j][k];
        }
        L[i][j] = (matrix[i][j] - sum) / L[j][j];
      }
    }
  }

  return L;
}
