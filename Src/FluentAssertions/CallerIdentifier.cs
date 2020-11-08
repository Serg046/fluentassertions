using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using FluentAssertions.Common;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace FluentAssertions
{
    /// <summary>
    /// Tries to extract the name of the variable or invocation on which the assertion is executed.
    /// </summary>
    public static class CallerIdentifier
    {
#pragma warning disable CA2211, SA1401, SA1307 // TODO: fix in 6.0
        public static Action<string> logger = _ => { };
#pragma warning restore SA1307, SA1401, CA2211
        private static readonly ConcurrentDictionary<string, ModuleDefinition> Modules = new ConcurrentDictionary<string, ModuleDefinition>();

        public static string DetermineCallerIdentity()
        {
            string caller = null;

            try
            {
                StackTrace stack = new StackTrace(fNeedFileInfo: true);

                foreach (StackFrame frame in stack.GetFrames())
                {
                    logger(frame.ToString());

                    if (frame.GetMethod() is object
                        && !IsDynamic(frame)
                        && !IsDotNet(frame)
                        && !IsCurrentAssembly(frame)
                        && !IsCustomAssertion(frame))
                    {
                        caller = ExtractVariableNameFrom(frame) ?? caller;
                        break;
                    }
                }
            }
            catch (Exception e)
            {
                // Ignore exceptions, as determination of caller identity is only a nice-to-have
                logger(e.ToString());
            }

            return caller;
        }

        private static readonly object Sync = new object();

        private static string ExtractVariableNameFrom(StackFrame frame)
        {
            // Synchronize it using a better way
            lock (Sync)
            {
                var method = frame.GetMethod();
                var assemblyLocation = method.Module.Assembly.Location;
                var module = Modules.GetOrAdd(assemblyLocation, loc => AssemblyDefinition
                    .ReadAssembly(assemblyLocation, new ReaderParameters { ReadSymbols = true }).MainModule);

                var methodDef = module.ImportReference(method).Resolve();
                var debugInfo = module.SymbolReader.Read(methodDef);

                var lineNumber = frame.GetFileLineNumber();
                var sequencePoint =
                    debugInfo.SequencePoints.FirstOrDefault(p => lineNumber >= p.StartLine && lineNumber <= p.EndLine);
                if (sequencePoint != null)
                {
                    return ExtractVariableNameFrom(methodDef, sequencePoint, debugInfo);
                }
            }

            return null;
        }

        private static string ExtractVariableNameFrom(MethodDefinition methodDef, SequencePoint sequencePoint, MethodDebugInformation debugInfo)
        {
            var instructions = new Stack<Instruction>();
            foreach (var instruction in methodDef.Body.Instructions.SkipWhile(cmd => cmd.Offset != sequencePoint.Offset))
            {
                if (instruction.Operand is MethodReference mRef && mRef.Name == "Should")
                {
                    var counter = mRef.Parameters.Count;
                    while (instructions.Count > 0)
                    {
                        var cmd = instructions.Pop();
                        var caller = TryGetFieldName(cmd)
                                     ?? TryGetPropertyName(cmd)
                                     ?? TryGetVariableName(cmd, debugInfo.Scope.Variables)
                                     ?? TryGetParameterName(cmd, methodDef.Parameters, methodDef.IsStatic);
                        if (caller != null && --counter == 0)
                        {
                            return caller;
                        }
                    }
                }

                instructions.Push(instruction);
            }

            return null;
        }

        private static string TryGetFieldName(Instruction instruction)
        {
            return (instruction.OpCode.Equals(OpCodes.Ldfld) || instruction.OpCode.Equals(OpCodes.Ldsfld))
                   && instruction.Operand is FieldReference field
                ? field.Name : null;
        }

        private static string TryGetPropertyName(Instruction instruction)
        {
            var method = instruction.Operand as MethodDefinition;
            if (method == null && instruction.Operand is MethodReference m)
            {
                method = m.Resolve();
            }

            return method != null && method.IsGetter && method.Name.StartsWith("get_", StringComparison.Ordinal)
                ? method.Name.Substring(4)
                : null;
        }

        private static string TryGetVariableName(Instruction instruction, IList<VariableDebugInformation> variables)
        {
            if (instruction.OpCode.Equals(OpCodes.Ldloc_0))
            {
                return variables[0].Name;
            }
            else if (instruction.OpCode.Equals(OpCodes.Ldloc_1))
            {
                return variables[1].Name;
            }
            else if (instruction.OpCode.Equals(OpCodes.Ldloc_2))
            {
                return variables[2].Name;
            }
            else if (instruction.OpCode.Equals(OpCodes.Ldloc_3))
            {
                return variables[3].Name;
            }
            else if (instruction.OpCode.Equals(OpCodes.Ldloc) || instruction.OpCode.Equals(OpCodes.Ldloc_S))
            {
                if (instruction.Operand is int idx)
                {
                    return variables[idx].Name;
                }
            }

            return null;
        }

        private static string TryGetParameterName(Instruction instruction, IList<ParameterDefinition> parameters, bool isStatic)
        {
            var offset = isStatic ? 0 : 1;
            if (instruction.OpCode.Equals(OpCodes.Ldarg_0))
            {
                return isStatic ? parameters[0].Name : null;
            }
            else if (instruction.OpCode.Equals(OpCodes.Ldarg_1))
            {
                return parameters[1 - offset].Name;
            }
            else if (instruction.OpCode.Equals(OpCodes.Ldarg_2))
            {
                return parameters[2 - offset].Name;
            }
            else if (instruction.OpCode.Equals(OpCodes.Ldarg_3))
            {
                return parameters[3 - offset].Name;
            }
            else if (instruction.OpCode.Equals(OpCodes.Ldarg) || instruction.OpCode.Equals(OpCodes.Ldarg_S))
            {
                if (instruction.Operand is int idx)
                {
                    var i = idx - offset;
                    return i >= 0 ? parameters[i].Name : null;
                }
            }

            return null;
        }

        private static bool IsCustomAssertion(StackFrame frame)
        {
            return frame.GetMethod().IsDecoratedWithOrInherit<CustomAssertionAttribute>();
        }

        private static bool IsDynamic(StackFrame frame)
        {
            return frame.GetMethod().DeclaringType is null;
        }

        private static bool IsCurrentAssembly(StackFrame frame)
        {
            return frame.GetMethod().DeclaringType.Assembly == typeof(CallerIdentifier).Assembly;
        }

        private static bool IsDotNet(StackFrame frame)
        {
            var frameNamespace = frame.GetMethod().DeclaringType.Namespace;
            var comparisonType = StringComparison.OrdinalIgnoreCase;

            return frameNamespace?.StartsWith("system.", comparisonType) == true ||
                frameNamespace?.Equals("system", comparisonType) == true;
        }
    }
}
