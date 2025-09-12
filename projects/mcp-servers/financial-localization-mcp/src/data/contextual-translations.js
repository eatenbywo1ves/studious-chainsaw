export const contextualTranslations = {
  // General financial context patterns
  general: {
    "es": {
      "prefixes": {
        "sub": "sub",
        "pre": "pre",
        "over": "sobre",
        "under": "sub",
        "multi": "multi"
      },
      "suffixes": {
        "ing": "ión",
        "tion": "ción",
        "sion": "sión",
        "ment": "miento",
        "ness": "dad",
        "able": "able",
        "ible": "ible"
      },
      "commonPatterns": {
        "market": "mercado",
        "price": "precio",
        "value": "valor",
        "rate": "tasa",
        "return": "rendimiento",
        "risk": "riesgo",
        "cost": "costo",
        "profit": "beneficio",
        "loss": "pérdida",
        "gain": "ganancia"
      }
    },
    "fr": {
      "prefixes": {
        "sub": "sous",
        "pre": "pré",
        "over": "sur",
        "under": "sous",
        "multi": "multi"
      },
      "suffixes": {
        "ing": "ation",
        "tion": "tion",
        "sion": "sion",
        "ment": "ment",
        "ness": "té",
        "able": "able",
        "ible": "ible"
      },
      "commonPatterns": {
        "market": "marché",
        "price": "prix",
        "value": "valeur",
        "rate": "taux",
        "return": "rendement",
        "risk": "risque",
        "cost": "coût",
        "profit": "profit",
        "loss": "perte",
        "gain": "gain"
      }
    },
    "de": {
      "prefixes": {
        "sub": "unter",
        "pre": "vor",
        "over": "über",
        "under": "unter",
        "multi": "multi"
      },
      "suffixes": {
        "ing": "ung",
        "tion": "tion",
        "sion": "sion",
        "ment": "ment",
        "ness": "keit",
        "able": "bar",
        "ible": "ibel"
      },
      "commonPatterns": {
        "market": "Markt",
        "price": "Preis",
        "value": "Wert",
        "rate": "Rate",
        "return": "Rendite",
        "risk": "Risiko",
        "cost": "Kosten",
        "profit": "Gewinn",
        "loss": "Verlust",
        "gain": "Gewinn"
      }
    },
    "ja": {
      "commonPatterns": {
        "market": "市場",
        "price": "価格",
        "value": "価値",
        "rate": "率",
        "return": "収益",
        "risk": "リスク",
        "cost": "コスト",
        "profit": "利益",
        "loss": "損失",
        "gain": "利得"
      },
      "prefixes": {
        "sub": "副",
        "pre": "事前",
        "over": "過度",
        "under": "過少",
        "multi": "多"
      }
    },
    "zh": {
      "commonPatterns": {
        "market": "市场",
        "price": "价格",
        "value": "价值",
        "rate": "利率",
        "return": "回报",
        "risk": "风险",
        "cost": "成本",
        "profit": "利润",
        "loss": "损失",
        "gain": "收益"
      },
      "prefixes": {
        "sub": "次",
        "pre": "预",
        "over": "过度",
        "under": "不足",
        "multi": "多"
      }
    }
  },

  // Options-specific patterns
  options: {
    "es": {
      "commonPatterns": {
        "call": "compra",
        "put": "venta",
        "strike": "ejercicio",
        "premium": "prima",
        "exercise": "ejercer",
        "expire": "vencer",
        "moneyness": "dinero",
        "intrinsic": "intrínseco",
        "time": "tiempo"
      },
      "phrases": {
        "in the money": "dentro del dinero",
        "out of the money": "fuera del dinero",
        "at the money": "en el dinero",
        "time decay": "decaimiento temporal",
        "implied volatility": "volatilidad implícita"
      }
    },
    "fr": {
      "commonPatterns": {
        "call": "achat",
        "put": "vente",
        "strike": "exercice",
        "premium": "prime",
        "exercise": "exercer",
        "expire": "expirer",
        "moneyness": "monnaie",
        "intrinsic": "intrinsèque",
        "time": "temps"
      },
      "phrases": {
        "in the money": "dans la monnaie",
        "out of the money": "hors de la monnaie",
        "at the money": "à la monnaie",
        "time decay": "décroissance temporelle",
        "implied volatility": "volatilité implicite"
      }
    },
    "de": {
      "commonPatterns": {
        "call": "Kauf",
        "put": "Verkauf",
        "strike": "Ausübung",
        "premium": "Prämie",
        "exercise": "ausüben",
        "expire": "verfallen",
        "moneyness": "Geld",
        "intrinsic": "innerer",
        "time": "Zeit"
      },
      "phrases": {
        "in the money": "im Geld",
        "out of the money": "aus dem Geld",
        "at the money": "am Geld",
        "time decay": "Zeitverfall",
        "implied volatility": "implizite Volatilität"
      }
    }
  },

  // Risk management patterns
  risk: {
    "es": {
      "commonPatterns": {
        "exposure": "exposición",
        "mitigation": "mitigación",
        "assessment": "evaluación",
        "tolerance": "tolerancia",
        "appetite": "apetito",
        "limit": "límite",
        "concentration": "concentración",
        "diversification": "diversificación"
      },
      "phrases": {
        "stress test": "prueba de estrés",
        "scenario analysis": "análisis de escenarios",
        "monte carlo": "monte carlo",
        "back testing": "prueba retrospectiva"
      }
    },
    "fr": {
      "commonPatterns": {
        "exposure": "exposition",
        "mitigation": "atténuation",
        "assessment": "évaluation",
        "tolerance": "tolérance",
        "appetite": "appétit",
        "limit": "limite",
        "concentration": "concentration",
        "diversification": "diversification"
      },
      "phrases": {
        "stress test": "test de stress",
        "scenario analysis": "analyse de scénarios",
        "monte carlo": "monte carlo",
        "back testing": "test rétrospectif"
      }
    },
    "de": {
      "commonPatterns": {
        "exposure": "Risiko",
        "mitigation": "Minderung",
        "assessment": "Bewertung",
        "tolerance": "Toleranz",
        "appetite": "Risikobereitschaft",
        "limit": "Limit",
        "concentration": "Konzentration",
        "diversification": "Diversifikation"
      },
      "phrases": {
        "stress test": "Stresstest",
        "scenario analysis": "Szenarioanalyse",
        "monte carlo": "Monte Carlo",
        "back testing": "Backtesting"
      }
    }
  },

  // Portfolio management patterns
  portfolio: {
    "es": {
      "commonPatterns": {
        "allocation": "asignación",
        "rebalancing": "reequilibrio",
        "optimization": "optimización",
        "performance": "rendimiento",
        "attribution": "atribución",
        "benchmark": "referencia",
        "tracking": "seguimiento",
        "active": "activo",
        "passive": "pasivo"
      },
      "phrases": {
        "asset allocation": "asignación de activos",
        "portfolio optimization": "optimización de cartera",
        "performance attribution": "atribución de rendimiento",
        "benchmark tracking": "seguimiento de referencia"
      }
    },
    "fr": {
      "commonPatterns": {
        "allocation": "allocation",
        "rebalancing": "rééquilibrage",
        "optimization": "optimisation",
        "performance": "performance",
        "attribution": "attribution",
        "benchmark": "référence",
        "tracking": "suivi",
        "active": "actif",
        "passive": "passif"
      },
      "phrases": {
        "asset allocation": "allocation d'actifs",
        "portfolio optimization": "optimisation de portefeuille",
        "performance attribution": "attribution de performance",
        "benchmark tracking": "suivi de référence"
      }
    },
    "de": {
      "commonPatterns": {
        "allocation": "Allokation",
        "rebalancing": "Neugewichtung",
        "optimization": "Optimierung",
        "performance": "Performance",
        "attribution": "Attribution",
        "benchmark": "Benchmark",
        "tracking": "Verfolgung",
        "active": "aktiv",
        "passive": "passiv"
      },
      "phrases": {
        "asset allocation": "Asset-Allokation",
        "portfolio optimization": "Portfolio-Optimierung",
        "performance attribution": "Performance-Attribution",
        "benchmark tracking": "Benchmark-Verfolgung"
      }
    }
  },

  // User interface patterns
  ui: {
    "es": {
      "buttons": {
        "start": "iniciar",
        "stop": "parar",
        "pause": "pausar",
        "reset": "reiniciar",
        "save": "guardar",
        "load": "cargar",
        "export": "exportar",
        "import": "importar"
      },
      "labels": {
        "settings": "configuración",
        "options": "opciones",
        "parameters": "parámetros",
        "results": "resultados",
        "summary": "resumen",
        "details": "detalles"
      }
    },
    "fr": {
      "buttons": {
        "start": "démarrer",
        "stop": "arrêter",
        "pause": "pause",
        "reset": "réinitialiser",
        "save": "sauvegarder",
        "load": "charger",
        "export": "exporter",
        "import": "importer"
      },
      "labels": {
        "settings": "paramètres",
        "options": "options",
        "parameters": "paramètres",
        "results": "résultats",
        "summary": "résumé",
        "details": "détails"
      }
    },
    "de": {
      "buttons": {
        "start": "starten",
        "stop": "stoppen",
        "pause": "pausieren",
        "reset": "zurücksetzen",
        "save": "speichern",
        "load": "laden",
        "export": "exportieren",
        "import": "importieren"
      },
      "labels": {
        "settings": "Einstellungen",
        "options": "Optionen",
        "parameters": "Parameter",
        "results": "Ergebnisse",
        "summary": "Zusammenfassung",
        "details": "Details"
      }
    },
    "ja": {
      "buttons": {
        "start": "開始",
        "stop": "停止",
        "pause": "一時停止",
        "reset": "リセット",
        "save": "保存",
        "load": "読み込み",
        "export": "エクスポート",
        "import": "インポート"
      },
      "labels": {
        "settings": "設定",
        "options": "オプション",
        "parameters": "パラメータ",
        "results": "結果",
        "summary": "要約",
        "details": "詳細"
      }
    },
    "zh": {
      "buttons": {
        "start": "开始",
        "stop": "停止",
        "pause": "暂停",
        "reset": "重置",
        "save": "保存",
        "load": "加载",
        "export": "导出",
        "import": "导入"
      },
      "labels": {
        "settings": "设置",
        "options": "选项",
        "parameters": "参数",
        "results": "结果",
        "summary": "摘要",
        "details": "详细信息"
      }
    }
  }
};