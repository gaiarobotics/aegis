/**
 * Vendor bundle entry point.
 *
 * Bundles Sigma.js v3, Graphology, and @sigma/node-border into
 * browser globals so the existing IIFE application scripts can
 * use them without a module system.
 *
 * Build:  npm run build
 */
import Sigma from "sigma";
import Graph from "graphology";
import { createNodeBorderProgram, NodeBorderProgram } from "@sigma/node-border";

window.Sigma = Sigma;
window.graphology = { Graph };
window.createNodeBorderProgram = createNodeBorderProgram;
window.NodeBorderProgram = NodeBorderProgram;
