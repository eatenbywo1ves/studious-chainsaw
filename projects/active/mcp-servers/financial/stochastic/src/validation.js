// Validation and error handling utilities for stochastic calculations

export class ValidationError extends Error {
  constructor(message, field, value) {
    super(message);
    this.name = 'ValidationError';
    this.field = field;
    this.value = value;
  }
}

export function validateStochasticParams(params, modelType) {
  const errors = [];

  // Common validations
  if (!params.steps || params.steps <= 0) {
    errors.push(new ValidationError('Steps must be a positive integer', 'steps', params.steps));
  }
  
  if (params.steps > 100000) {
    errors.push(new ValidationError('Steps cannot exceed 100000 for performance reasons', 'steps', params.steps));
  }

  if (!params.timeHorizon || params.timeHorizon <= 0) {
    errors.push(new ValidationError('Time horizon must be positive', 'timeHorizon', params.timeHorizon));
  }

  if (params.timeHorizon > 100) {
    errors.push(new ValidationError('Time horizon cannot exceed 100 years', 'timeHorizon', params.timeHorizon));
  }

  // Model-specific validations
  switch (modelType) {
    case 'GBM':
      if (params.sigma < 0) {
        errors.push(new ValidationError('Volatility must be non-negative', 'sigma', params.sigma));
      }
      if (params.sigma > 10) {
        errors.push(new ValidationError('Volatility seems unrealistically high (>1000%)', 'sigma', params.sigma));
      }
      if (params.initialPrice <= 0) {
        errors.push(new ValidationError('Initial price must be positive', 'initialPrice', params.initialPrice));
      }
      break;

    case 'OU':
      if (params.kappa <= 0) {
        errors.push(new ValidationError('Mean reversion speed must be positive', 'kappa', params.kappa));
      }
      if (params.theta <= 0) {
        errors.push(new ValidationError('Long-term mean must be positive', 'theta', params.theta));
      }
      if (params.sigma < 0) {
        errors.push(new ValidationError('Volatility must be non-negative', 'sigma', params.sigma));
      }
      break;

    case 'Heston':
      if (params.kappa <= 0) {
        errors.push(new ValidationError('Volatility mean reversion speed must be positive', 'kappa', params.kappa));
      }
      if (params.theta <= 0) {
        errors.push(new ValidationError('Long-term variance must be positive', 'theta', params.theta));
      }
      if (params.xi <= 0) {
        errors.push(new ValidationError('Vol of vol must be positive', 'xi', params.xi));
      }
      if (Math.abs(params.rho) > 1) {
        errors.push(new ValidationError('Correlation must be between -1 and 1', 'rho', params.rho));
      }
      if (params.initialVar <= 0) {
        errors.push(new ValidationError('Initial variance must be positive', 'initialVar', params.initialVar));
      }
      // Feller condition check
      if (2 * params.kappa * params.theta <= params.xi * params.xi) {
        console.warn('Warning: Feller condition not satisfied - variance may become negative');
      }
      break;

    case 'Merton':
      if (params.sigma < 0) {
        errors.push(new ValidationError('Diffusion volatility must be non-negative', 'sigma', params.sigma));
      }
      if (params.lambda < 0) {
        errors.push(new ValidationError('Jump intensity must be non-negative', 'lambda', params.lambda));
      }
      if (params.sigmaJ < 0) {
        errors.push(new ValidationError('Jump volatility must be non-negative', 'sigmaJ', params.sigmaJ));
      }
      break;

    case 'CIR':
      if (params.kappa <= 0) {
        errors.push(new ValidationError('Mean reversion speed must be positive', 'kappa', params.kappa));
      }
      if (params.theta <= 0) {
        errors.push(new ValidationError('Long-term rate must be positive', 'theta', params.theta));
      }
      if (params.sigma < 0) {
        errors.push(new ValidationError('Volatility must be non-negative', 'sigma', params.sigma));
      }
      if (params.initialRate < 0) {
        errors.push(new ValidationError('Initial rate must be non-negative', 'initialRate', params.initialRate));
      }
      // Feller condition for CIR
      if (2 * params.kappa * params.theta <= params.sigma * params.sigma) {
        console.warn('Warning: Feller condition not satisfied - rate may become negative');
      }
      break;
  }

  return errors;
}

export function sanitizeNumericValue(value, defaultValue = 0) {
  if (value === undefined || value === null || isNaN(value)) {
    return defaultValue;
  }
  if (!isFinite(value)) {
    return defaultValue;
  }
  return value;
}

export function clampValue(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

export function validatePath(path) {
  if (!Array.isArray(path)) {
    throw new ValidationError('Path must be an array', 'path', path);
  }
  
  if (path.length < 2) {
    throw new ValidationError('Path must contain at least 2 points', 'path', path);
  }

  for (let i = 0; i < path.length; i++) {
    const point = path[i];
    if (!point || typeof point !== 'object') {
      throw new ValidationError(`Invalid point at index ${i}`, 'path', point);
    }
    
    if (point.price !== undefined && (isNaN(point.price) || !isFinite(point.price) || point.price < 0)) {
      throw new ValidationError(`Invalid price at index ${i}`, 'price', point.price);
    }
    
    if (point.rate !== undefined && (isNaN(point.rate) || !isFinite(point.rate))) {
      throw new ValidationError(`Invalid rate at index ${i}`, 'rate', point.rate);
    }
  }
  
  return true;
}