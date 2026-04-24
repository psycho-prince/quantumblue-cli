from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.analyses.operations.binary import BinaryType

class PrecisionLeak(AbstractDetector):
    ARGUMENT = 'precision-leak'
    HELP = 'Detects 18->6 decimal truncation without refunding/reverting dust'
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/your-repo/quantumblue/docs/precision-leak"

    def _detect(self):
        results = []
        for contract in self.compilation_unit.contracts:
            for func in contract.functions:
                for node in func.nodes:
                    for ir in node.irs:
                        # Logic: Find Division followed by Multiplication (Truncation Pattern)
                        if isinstance(ir, BinaryType.DIVISION):
                            # Check if the result (lvalue) is used in a subsequent Multiplication
                            for next_ir in node.irs:
                                if isinstance(next_ir, BinaryType.MULTIPLICATION) and ir.lvalue in next_ir.used_variables:
                                    
                                    # CHECK: Is there a Modulo (%) check in this function to handle dust?
                                    has_modulo = any('%' in str(n) for n in func.nodes)
                                    
                                    if not has_modulo:
                                        info = [f"Precision Leak in {func.name}: Truncation detected without dust handling.\n", node]
                                        res = self.generate_result(info)
                                        results.append(res)
        return results
