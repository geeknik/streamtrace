import type { Component } from "solid-js";
import { createSignal, createResource, onMount, onCleanup, Show } from "solid-js";
import { fetchEntityGraph } from "../../api/entities";
import { ApiError } from "../../api/client";
import type { EntityGraph as EntityGraphType, Entity, EntityRelationship } from "../../api/types";

interface EntityGraphProps {
  entityId: string;
  onSelectEntity: (id: string) => void;
}

interface GraphNode {
  id: string;
  label: string;
  entityType: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  isCenter: boolean;
}

interface GraphEdge {
  source: string;
  target: string;
  label: string;
}

const TYPE_COLORS: Record<string, string> = {
  user: "#58a6ff",
  ip: "#3fb950",
  device: "#a371f7",
  host: "#d29922",
};

const NODE_RADIUS = 20;
const CANVAS_WIDTH = 800;
const CANVAS_HEIGHT = 500;
const REPULSION = 5000;
const SPRING_K = 0.01;
const DAMPING = 0.85;
const SIMULATION_STEPS = 120;

function buildGraph(
  data: EntityGraphType,
): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodeMap = new Map<string, GraphNode>();

  function addNode(entity: Entity, isCenter: boolean): void {
    if (nodeMap.has(entity.id)) return;
    const angle = Math.random() * 2 * Math.PI;
    const radius = isCenter ? 0 : 80 + Math.random() * 100;
    nodeMap.set(entity.id, {
      id: entity.id,
      label: entity.display_name ?? entity.identifier,
      entityType: entity.entity_type,
      x: CANVAS_WIDTH / 2 + Math.cos(angle) * radius,
      y: CANVAS_HEIGHT / 2 + Math.sin(angle) * radius,
      vx: 0,
      vy: 0,
      isCenter,
    });
  }

  addNode(data.center, true);
  for (const entity of data.entities) {
    addNode(entity, entity.id === data.center.id);
  }

  const edges: GraphEdge[] = data.relationships.map(
    (rel: EntityRelationship) => ({
      source: rel.source_entity,
      target: rel.target_entity,
      label: rel.relationship,
    }),
  );

  return { nodes: Array.from(nodeMap.values()), edges };
}

function simulate(nodes: GraphNode[], edges: GraphEdge[]): void {
  for (let step = 0; step < SIMULATION_STEPS; step++) {
    // Repulsion between all pairs
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[j].x - nodes[i].x;
        const dy = nodes[j].y - nodes[i].y;
        const distSq = Math.max(dx * dx + dy * dy, 1);
        const force = REPULSION / distSq;
        const dist = Math.sqrt(distSq);
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        nodes[i].vx -= fx;
        nodes[i].vy -= fy;
        nodes[j].vx += fx;
        nodes[j].vy += fy;
      }
    }

    // Spring attraction along edges
    const nodeById = new Map(nodes.map((n) => [n.id, n]));
    for (const edge of edges) {
      const src = nodeById.get(edge.source);
      const tgt = nodeById.get(edge.target);
      if (!src || !tgt) continue;
      const dx = tgt.x - src.x;
      const dy = tgt.y - src.y;
      const fx = dx * SPRING_K;
      const fy = dy * SPRING_K;
      src.vx += fx;
      src.vy += fy;
      tgt.vx -= fx;
      tgt.vy -= fy;
    }

    // Apply velocities and damping
    for (const node of nodes) {
      node.vx *= DAMPING;
      node.vy *= DAMPING;
      node.x += node.vx;
      node.y += node.vy;
      // Keep within bounds
      node.x = Math.max(NODE_RADIUS, Math.min(CANVAS_WIDTH - NODE_RADIUS, node.x));
      node.y = Math.max(NODE_RADIUS, Math.min(CANVAS_HEIGHT - NODE_RADIUS, node.y));
    }
  }
}

function drawGraph(
  ctx: CanvasRenderingContext2D,
  nodes: GraphNode[],
  edges: GraphEdge[],
): void {
  ctx.clearRect(0, 0, CANVAS_WIDTH, CANVAS_HEIGHT);

  const nodeById = new Map(nodes.map((n) => [n.id, n]));

  // Draw edges
  ctx.strokeStyle = "#30363d";
  ctx.lineWidth = 1;
  for (const edge of edges) {
    const src = nodeById.get(edge.source);
    const tgt = nodeById.get(edge.target);
    if (!src || !tgt) continue;
    ctx.beginPath();
    ctx.moveTo(src.x, src.y);
    ctx.lineTo(tgt.x, tgt.y);
    ctx.stroke();

    // Edge label at midpoint
    const mx = (src.x + tgt.x) / 2;
    const my = (src.y + tgt.y) / 2;
    ctx.fillStyle = "#6e7681";
    ctx.font = "10px sans-serif";
    ctx.textAlign = "center";
    ctx.fillText(edge.label, mx, my - 4);
  }

  // Draw nodes
  for (const node of nodes) {
    const color = TYPE_COLORS[node.entityType] ?? "#8b949e";

    ctx.beginPath();
    ctx.arc(node.x, node.y, NODE_RADIUS, 0, Math.PI * 2);
    ctx.fillStyle = node.isCenter ? color : `${color}88`;
    ctx.fill();
    if (node.isCenter) {
      ctx.strokeStyle = "#e1e4e8";
      ctx.lineWidth = 2;
      ctx.stroke();
    }

    // Label
    ctx.fillStyle = "#e1e4e8";
    ctx.font = "11px sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    const truncated =
      node.label.length > 12 ? node.label.slice(0, 11) + "..." : node.label;
    ctx.fillText(truncated, node.x, node.y + NODE_RADIUS + 12);
  }
}

async function loadGraph(id: string): Promise<EntityGraphType> {
  return fetchEntityGraph(id, 2);
}

const EntityGraph: Component<EntityGraphProps> = (props) => {
  let canvasRef: HTMLCanvasElement | undefined;
  const [graphData] = createResource(() => props.entityId, loadGraph);
  const [nodes, setNodes] = createSignal<GraphNode[]>([]);
  const [edges, setEdges] = createSignal<GraphEdge[]>([]);

  let animFrame: number | undefined;

  function render(): void {
    if (!canvasRef) return;
    const ctx = canvasRef.getContext("2d");
    if (!ctx) return;
    drawGraph(ctx, nodes(), edges());
  }

  function handleCanvasClick(e: MouseEvent): void {
    if (!canvasRef) return;
    const rect = canvasRef.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    for (const node of nodes()) {
      const dx = node.x - mx;
      const dy = node.y - my;
      if (dx * dx + dy * dy <= NODE_RADIUS * NODE_RADIUS) {
        props.onSelectEntity(node.id);
        return;
      }
    }
  }

  onMount(() => {
    // Re-render when data loads (via effect)
  });

  onCleanup(() => {
    if (animFrame !== undefined) {
      cancelAnimationFrame(animFrame);
    }
  });

  // Use createEffect-like pattern via resource tracking
  function updateGraph(): void {
    const data = graphData();
    if (!data) return;
    const { nodes: n, edges: e } = buildGraph(data);
    simulate(n, e);
    setNodes(n);
    setEdges(e);
    animFrame = requestAnimationFrame(render);
  }

  // Track resource changes
  const renderWatcher = (): void => {
    if (graphData.state === "ready") {
      updateGraph();
    }
  };

  // We use an effect by calling renderWatcher from JSX signal tracking
  return (
    <div class="entity-graph-container">
      <Show when={graphData.error}>
        <div class="error-msg" role="alert">
          {graphData.error instanceof ApiError
            ? `${(graphData.error as ApiError).code}: ${(graphData.error as ApiError).message}`
            : "Failed to load entity graph"}
        </div>
      </Show>

      <Show when={graphData.loading}>
        <div class="loading" aria-live="polite">
          Loading graph...
        </div>
      </Show>

      <Show when={graphData()}>
        {(_data) => {
          // Trigger update on data change
          queueMicrotask(updateGraph);
          return (
            <canvas
              ref={canvasRef}
              width={CANVAS_WIDTH}
              height={CANVAS_HEIGHT}
              class="entity-graph-canvas"
              onClick={handleCanvasClick}
              role="img"
              aria-label="Entity relationship graph"
            />
          );
        }}
      </Show>

      {/* Hidden element to track reactivity */}
      <span style={{ display: "none" }}>{void renderWatcher()}</span>
    </div>
  );
};

export default EntityGraph;
