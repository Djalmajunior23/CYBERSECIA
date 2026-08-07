"""
LLM Client — Integração com AI Studio, OpenAI, Claude para Agentes
Suporta: Google AI Studio, OpenAI GPT-4, Anthropic Claude
"""
import os
import json
import logging
from typing import Dict, Any, Optional, List
import httpx

logger = logging.getLogger("llm.client")

class LLMClient:
    """
    Cliente unificado para múltiplos provedores LLM.
    Usado pelos agentes para análise inteligente, geração de hipóteses,
    e tomada de decisão assistida por IA.
    """

    PROVIDERS = {
        "google": {
            "base_url": "https://generativelanguage.googleapis.com/v1beta",
            "model": "gemini-1.5-pro",
            "key_env": "AI_STUDIO_API_KEY"
        },
        "openai": {
            "base_url": "https://api.openai.com/v1",
            "model": "gpt-4o",
            "key_env": "OPENAI_API_KEY"
        },
        "anthropic": {
            "base_url": "https://api.anthropic.com/v1",
            "model": "claude-3-5-sonnet-20240620",
            "key_env": "ANTHROPIC_API_KEY"
        }
    }

    def __init__(self, provider: str = "google", system_prompt: str = ""):
        self.provider = provider.lower()
        self.config = self.PROVIDERS.get(self.provider)
        if not self.config:
            raise ValueError(f"Provedor não suportado: {provider}")

        self.api_key = os.getenv(self.config["key_env"], "")
        self.base_url = self.config["base_url"]
        self.model = self.config["model"]
        self.system_prompt = system_prompt
        self.client = httpx.AsyncClient(timeout=60.0)

    async def analyze(self, prompt: str, temperature: float = 0.1, max_tokens: int = 4096) -> Dict[str, Any]:
        """Envia prompt para LLM e retorna resposta estruturada."""
        if not self.api_key:
            logger.warning(f"API key não configurada para {self.provider}. Usando fallback simulado.")
            return self._fallback_response(prompt)

        try:
            if self.provider == "google":
                return await self._call_google(prompt, temperature, max_tokens)
            elif self.provider == "openai":
                return await self._call_openai(prompt, temperature, max_tokens)
            elif self.provider == "anthropic":
                return await self._call_anthropic(prompt, temperature, max_tokens)
        except Exception as e:
            logger.error(f"Erro LLM {self.provider}: {e}")
            return self._fallback_response(prompt)

    async def _call_google(self, prompt: str, temperature: float, max_tokens: int) -> Dict:
        url = f"{self.base_url}/models/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "contents": [{"role": "user", "parts": [{"text": self.system_prompt + "\n\n" + prompt}]}],
            "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens}
        }
        resp = await self.client.post(url, json=payload)
        data = resp.json()
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        return {"success": True, "text": text, "provider": "google", "model": self.model}

    async def _call_openai(self, prompt: str, temperature: float, max_tokens: int) -> Dict:
        url = f"{self.base_url}/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": prompt}
            ],
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        resp = await self.client.post(url, headers=headers, json=payload)
        data = resp.json()
        text = data["choices"][0]["message"]["content"]
        return {"success": True, "text": text, "provider": "openai", "model": self.model}

    async def _call_anthropic(self, prompt: str, temperature: float, max_tokens: int) -> Dict:
        url = f"{self.base_url}/messages"
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": self.system_prompt,
            "messages": [{"role": "user", "content": prompt}]
        }
        resp = await self.client.post(url, headers=headers, json=payload)
        data = resp.json()
        text = data["content"][0]["text"]
        return {"success": True, "text": text, "provider": "anthropic", "model": self.model}

    def _fallback_response(self, prompt: str) -> Dict:
        """Resposta simulada quando API key não está disponível."""
        return {
            "success": True,
            "text": f"[SIMULADO] Análise do prompt: '{prompt[:100]}...' — Configure a API key em .env para respostas reais.",
            "provider": "fallback",
            "model": "none"
        }

    async def analyze_threat(self, ioc_data: Dict) -> Dict:
        """Análise especializada de ameaças com contexto de cibersegurança."""
        prompt = f"""
Analise o seguinte IOC (Indicator of Compromise) e forneça:
1. Probabilidade de ser malicioso (0-100%)
2. Possível ator de ameaça associado
3. Técnicas MITRE ATT&CK mapeadas
4. Recomendações de contenção

Dados do IOC:
{json.dumps(ioc_data, indent=2, ensure_ascii=False)}

Responda em JSON com as chaves: malicious_probability, threat_actor, mitre_techniques, recommendations.
"""
        result = await self.analyze(prompt, temperature=0.1)
        try:
            # Tentar extrair JSON da resposta
            text = result["text"]
            # Procurar JSON entre ```json e ```
            if "```json" in text:
                json_str = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                json_str = text.split("```")[1].split("```")[0]
            else:
                json_str = text
            parsed = json.loads(json_str.strip())
            result["structured"] = parsed
        except Exception as e:
            result["structured"] = {"error": f"Não foi possível parsear JSON: {e}", "raw": result["text"]}
        return result

    async def generate_hypothesis(self, telemetry: List[Dict]) -> Dict:
        """Gera hipóteses de caça a ameaças baseadas em telemetria."""
        prompt = f"""
Você é um Threat Hunter especialista. Analise os seguintes eventos de telemetria e gere 3 hipóteses de caça.
Cada hipótese deve incluir: descrição, MITRE ATT&CK technique ID, query Splunk sugerida, e nível de confiança.

Eventos:
{json.dumps(telemetry, indent=2, ensure_ascii=False)}

Responda em JSON com array de hipóteses.
"""
        result = await self.analyze(prompt, temperature=0.3)
        try:
            text = result["text"]
            if "```json" in text:
                json_str = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                json_str = text.split("```")[1].split("```")[0]
            else:
                json_str = text
            result["hypotheses"] = json.loads(json_str.strip())
        except Exception:
            result["hypotheses"] = []
        return result

    async def review_vulnerability(self, vuln_data: Dict) -> Dict:
        """Análise de vulnerabilidade com contexto de negócio."""
        prompt = f"""
Analise a seguinte vulnerabilidade e forneça:
1. Risco de negócio (baixo/médio/alto/crítico)
2. Probabilidade de exploração em nosso ambiente
3. Passos de remediação prioritários
4. Impacto na conformidade (LGPD, ISO 27001)

Vulnerabilidade:
{json.dumps(vuln_data, indent=2, ensure_ascii=False)}
"""
        return await self.analyze(prompt, temperature=0.2)
