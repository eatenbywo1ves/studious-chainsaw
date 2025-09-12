"""
Enhanced Strategy Selection for Von Neumann Agent

Improves strategy selection based on problem characteristics
"""

from typing import Dict, List, Any
from meta_reasoning import ReasoningStrategy
import re


class EnhancedStrategySelector:
    """Enhanced strategy selector using problem analysis"""
    
    def __init__(self):
        # Define strategy selection rules based on problem characteristics
        self.strategy_rules = {
            # Game-theoretic keywords -> game theory strategy
            ReasoningStrategy.GAME_THEORETIC: [
                'game', 'player', 'strategy', 'competition', 'compete', 
                'optimize', 'strategic', 'opponent', 'payoff', 'equilibrium',
                'minimax', 'zero-sum', 'nash'
            ],
            
            # Probabilistic keywords -> Bayesian strategy  
            ReasoningStrategy.PROBABILISTIC_INFERENCE: [
                'probability', 'uncertain', 'chance', 'likely', 'random',
                'stochastic', 'belief', 'evidence', 'bayesian', 'inference',
                'distribution', 'risk', 'uncertainty'
            ],
            
            # Computational keywords -> computational strategy
            ReasoningStrategy.COMPUTATIONAL: [
                'compute', 'calculate', 'solve', 'equation', 'algorithm',
                'numerical', 'linear', 'system', 'matrix', 'stability',
                'optimization', 'minimize', 'maximize'
            ],
            
            # Cross-domain keywords -> analogical/interdisciplinary
            ReasoningStrategy.ANALOGICAL: [
                'similar', 'like', 'analogy', 'analogous', 'compare',
                'relates', 'relationship', 'connection', 'parallel'
            ],
            
            ReasoningStrategy.INTERDISCIPLINARY: [
                'biology', 'physics', 'economics', 'computer science',
                'evolution', 'selection', 'market', 'force', 'energy',
                'cross-domain', 'interdisciplinary', 'unify', 'unified'
            ]
        }
    
    def select_strategy(self, problem_description: str, 
                       problem_analysis: Dict[str, Any]) -> ReasoningStrategy:
        """Select the best strategy based on problem characteristics"""
        
        desc_lower = problem_description.lower()
        strategy_scores = {}
        
        # Score each strategy based on keyword matches
        for strategy, keywords in self.strategy_rules.items():
            score = 0
            for keyword in keywords:
                if keyword in desc_lower:
                    score += 1
                    
            # Weight by analysis factors
            if strategy == ReasoningStrategy.GAME_THEORETIC:
                score += len(problem_analysis.get('strategic_elements', [])) * 2
                
            elif strategy == ReasoningStrategy.PROBABILISTIC_INFERENCE:
                score += len(problem_analysis.get('uncertainty_factors', [])) * 2
                
            elif strategy == ReasoningStrategy.COMPUTATIONAL:
                math_ops = problem_analysis.get('mathematical_content', {}).get('operations', [])
                score += len(math_ops) * 2
                
            elif strategy in [ReasoningStrategy.ANALOGICAL, ReasoningStrategy.INTERDISCIPLINARY]:
                score += problem_analysis.get('cross_domain_potential', 0) * 5
            
            if score > 0:
                strategy_scores[strategy] = score
        
        # Select strategy with highest score
        if strategy_scores:
            best_strategy = max(strategy_scores.items(), key=lambda x: x[1])[0]
            return best_strategy
        
        # Default fallback
        return self._select_fallback_strategy(problem_analysis)
    
    def _select_fallback_strategy(self, problem_analysis: Dict[str, Any]) -> ReasoningStrategy:
        """Select fallback strategy based on problem type"""
        
        problem_type = problem_analysis.get('problem_type', 'general')
        
        fallback_map = {
            'strategic': ReasoningStrategy.GAME_THEORETIC,
            'probabilistic': ReasoningStrategy.PROBABILISTIC_INFERENCE,
            'computational': ReasoningStrategy.COMPUTATIONAL,
            'optimization': ReasoningStrategy.COMPUTATIONAL,
            'analogical': ReasoningStrategy.ANALOGICAL,
            'general': ReasoningStrategy.LOGICAL_DEDUCTION
        }
        
        return fallback_map.get(problem_type, ReasoningStrategy.LOGICAL_DEDUCTION)
    
    def get_strategy_confidence(self, strategy: ReasoningStrategy, 
                              problem_description: str,
                              problem_analysis: Dict[str, Any]) -> float:
        """Get confidence in the selected strategy"""
        
        desc_lower = problem_description.lower()
        
        if strategy in self.strategy_rules:
            keywords = self.strategy_rules[strategy]
            matches = sum(1 for keyword in keywords if keyword in desc_lower)
            confidence = min(0.9, 0.5 + (matches * 0.1))
            return confidence
        
        return 0.6  # Default confidence