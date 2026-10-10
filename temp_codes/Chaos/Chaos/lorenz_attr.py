import numpy as np
import matplotlib.pyplot as plt
from scipy.integrate import odeint

# 1. Define the Lorenz system equations
def lorenz(state, t, sigma, rho, beta):
    x, y, z = state
    return [sigma * (y - x), x * (rho - z) - y, x * y - beta * z]

# 2. Set parameters (Standard chaos values)
sigma, rho, beta = 10.0, 28.0, 8/3.0
t = np.linspace(0, 40, 4000) # Time span

# 3. Define two nearly identical starting points
initial_state1 = [1.0, 1.0, 1.0]
initial_state2 = [1.00001, 1.0, 1.0] # Only 0.00001 difference!

# 4. Solve for both paths
path1 = odeint(lorenz, initial_state1, t, args=(sigma, rho, beta))
path2 = odeint(lorenz, initial_state2, t, args=(sigma, rho, beta))

# 5. Visualize the divergence
fig = plt.figure(figsize=(12, 5))

# Plot 1: 3D Visualization
ax1 = fig.add_subplot(121, projection='3d')
ax1.plot(path1[:,0], path1[:,1], path1[:,2], color='blue', alpha=0.7, label='Start A')
ax1.plot(path2[:,0], path2[:,1], path2[:,2], color='red', alpha=0.5, label='Start B')
ax1.set_title("3D Lorenz Attractor")
ax1.legend()

# Plot 2: X-coordinate over time (Shows the moment of divergence)
ax2 = fig.add_subplot(122)
ax2.plot(t, path1[:,0], color='blue', label='Path A')
ax2.plot(t, path2[:,0], color='red', linestyle='--', label='Path B')
ax2.set_title("Divergence over Time (X-axis)")
ax2.set_xlabel("Time")
ax2.legend()

plt.show()
