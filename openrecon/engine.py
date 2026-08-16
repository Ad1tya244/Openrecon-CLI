import asyncio
import inspect
import importlib
import logging
from functools import partial
from typing import Dict, Any, List, Optional, Callable
from openrecon.modules import MODULE_REGISTRY
from openrecon.config import settings

logger = logging.getLogger("openrecon.engine")

class ScanEngine:
    """
    Local reconnaissance scan engine.
    Executes modules safely and concurrently without any web API dependencies.
    """
    def __init__(self, timeout: float = settings.MODULE_TIMEOUT):
        self.timeout = timeout

    async def _execute_module_func(self, func, is_async: bool, target: str, timeout: float) -> Any:
        loop = asyncio.get_running_loop()
        try:
            if is_async or inspect.iscoroutinefunction(func):
                return await asyncio.wait_for(func(target), timeout=timeout)
            else:
                return await asyncio.wait_for(
                    loop.run_in_executor(None, partial(func, target)),
                    timeout=timeout
                )
        except asyncio.TimeoutError:
            return {"error": f"Module timed out after {timeout} seconds"}
        except Exception as e:
            return {"error": f"Module execution error: {str(e)}"}

    async def run_module(self, module_key: str, target: str, timeout: Optional[float] = None) -> Dict[str, Any]:
        """
        Runs a single recon module by key (e.g. 'dns', 'ssl', 'whois').
        """
        mod_key = module_key.lower().strip()
        if mod_key not in MODULE_REGISTRY:
            # Check if matching by partial name
            matched = [k for k in MODULE_REGISTRY if mod_key in k]
            if matched:
                mod_key = matched[0]
            else:
                return {"error": f"Unknown module: '{module_key}'. Use 'openrecon list-modules' to view available modules."}

        meta = MODULE_REGISTRY[mod_key]
        mod_timeout = timeout or self.timeout

        try:
            mod_obj = importlib.import_module(meta["module"])
            func = getattr(mod_obj, meta["func"])
        except Exception as e:
            return {"error": f"Failed to load module '{mod_key}': {str(e)}"}

        result = await self._execute_module_func(func, meta.get("async", True), target, mod_timeout)
        return {
            "module_key": mod_key,
            "name": meta["name"],
            "data": result
        }

    async def run_modules(
        self,
        module_keys: List[str],
        target: str,
        on_progress: Optional[Callable[[str, str, Any], None]] = None
    ) -> Dict[str, Any]:
        """
        Runs multiple modules concurrently.
        Optional callback `on_progress(mod_key, status, result)` is called as each completes.
        """
        results = {
            "target": target,
            "modules": {}
        }

        async def _run_and_notify(k: str):
            if on_progress:
                on_progress(k, "running", None)
            res = await self.run_module(k, target)
            if on_progress:
                on_progress(k, "done", res)
            return k, res

        tasks = [_run_and_notify(k) for k in module_keys if k in MODULE_REGISTRY]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        for item in completed:
            if isinstance(item, tuple):
                k, res = item
                results["modules"][k] = res
            elif isinstance(item, Exception):
                logger.error(f"Unexpected error in module runner: {item}")

        return results

    async def run_all(
        self,
        target: str,
        on_progress: Optional[Callable[[str, str, Any], None]] = None
    ) -> Dict[str, Any]:
        """
        Runs all registered reconnaissance modules concurrently.
        """
        all_keys = list(MODULE_REGISTRY.keys())
        return await self.run_modules(all_keys, target, on_progress=on_progress)
